#!/usr/bin/env python3
"""Bounded Sahara ELF metadata probe; never sends segment contents.

The probe enters image-transfer-pending mode, supplies a standard 64-byte
ELF64/AArch64 header, then supplies one minimal, non-executable PT_LOAD
program header. If the PBL requests the segment byte, the host records that request
and stops without sending it. No loader, executable bytes, hash table, or
storage-write command is sent. A PBL/parser stall may require a full power
cycle before the next test.
"""

from __future__ import annotations

import struct
import sys
import argparse

import usb.backend.libusb1
import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
TIMEOUT_MS = 3000
READ_SIZE = 0x1000

HELLO = 0x01
HELLO_RESP = 0x02
READ_DATA64 = 0x12
END_IMAGE_TX = 0x04
IMAGE_ID = 13


def read_packet(ep_in) -> bytes:
    return bytes(ep_in.read(READ_SIZE, timeout=TIMEOUT_MS))


def packet_header(packet: bytes) -> tuple[int, int]:
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara packet ({len(packet)} bytes): {packet.hex()}")
    return struct.unpack_from("<II", packet)


def read_data64_fields(packet: bytes) -> tuple[int, int, int, int]:
    command, length = packet_header(packet)
    if command != READ_DATA64 or length < 32 or len(packet) < 32:
        raise RuntimeError(f"not a complete READ_DATA64 packet: {packet.hex()}")
    image_id, reserved = struct.unpack_from("<II", packet, 8)
    offset, requested = struct.unpack_from("<QQ", packet, 16)
    return image_id, reserved, offset, requested


def show_response(packet: bytes, label: str) -> bool:
    command, length = packet_header(packet)
    if command == END_IMAGE_TX:
        detail = packet[:length].hex() if length <= len(packet) else packet.hex()
        print(f"{label}: END_IMAGE_TX raw={detail}")
        return False
    if command != READ_DATA64 or length < 32 or len(packet) < 32:
        print(f"{label}: unexpected packet raw={packet.hex()}")
        return False
    image_id, reserved, offset, requested = read_data64_fields(packet)
    print(
        f"{label}: READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
        f"offset=0x{offset:x} length=0x{requested:x}"
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--resume-after-initial-request",
        action="store_true",
        help="continue only after this probe already observed request image 13, offset 0, length 64",
    )
    args = parser.parse_args()

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("ERROR: libusb backend unavailable", file=sys.stderr)
        return 2

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("No Qualcomm EDL device (05c6:9008) is visible to libusb.")
        return 3

    try:
        try:
            dev.set_configuration()
        except usb.core.USBError:
            pass

        intf = dev.get_active_configuration()[(0, 0)]
        ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress)
            == usb.util.ENDPOINT_OUT,
        )
        ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda ep: usb.util.endpoint_direction(ep.bEndpointAddress)
            == usb.util.ENDPOINT_IN,
        )
        if ep_in is None or ep_out is None:
            print("ERROR: Sahara bulk endpoints unavailable", file=sys.stderr)
            return 4

        if args.resume_after_initial_request:
            # The caller observed and consumed READ_DATA64(image=13, offset=0,
            # length=64) in this same live probe, then stopped before sending data.
            print("Resuming same probe after confirmed initial request image_id=13 offset=0 length=64")
        else:
            hello = read_packet(ep_in)
            if len(hello) < 0x30:
                print(f"Unexpected short initial packet ({len(hello)} bytes): {hello.hex()}")
                return 5
            fields = struct.unpack_from("<12I", hello)
            if fields[0] != HELLO or fields[1] != 0x30:
                print(f"Unexpected initial Sahara packet: {hello.hex()}")
                return 6
            version, version_min = fields[2], fields[3]
            print(
                f"HELLO version={version} min={version_min} "
                f"max_cmd_len={fields[4]} mode={fields[5]}"
            )

            # Ask only for ordinary programmer-transfer parsing; no programmer follows.
            hello_resp = struct.pack(
                "<12I", HELLO_RESP, 0x30, version, version_min, 0, 0, 0, 0, 0, 0, 0, 0
            )
            ep_out.write(hello_resp, timeout=TIMEOUT_MS)
            request = read_packet(ep_in)
            command, length = packet_header(request)
            if command != READ_DATA64 or length < 32 or len(request) < 32:
                show_response(request, "Initial transfer state")
                return 0
            image_id, reserved, offset, requested = read_data64_fields(request)
            print(
                f"Initial request: image_id={image_id} reserved=0x{reserved:x} "
                f"offset=0x{offset:x} length=0x{requested:x}"
            )
            if (image_id, offset, requested) != (IMAGE_ID, 0, 64):
                print("Unexpected initial request; stopping without sending image data.")
                return 0

        # One empty-sections ELF64/AArch64 header with exactly one PHDR at offset 64.
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
            2,      # ET_EXEC
            183,    # EM_AARCH64
            1,
            0,      # entry: no entry point
            64,     # e_phoff
            0,      # e_shoff
            0,
            64,     # e_ehsize
            56,     # e_phentsize
            1,      # e_phnum
            0,
            0,
            0,
        )
        if len(elf_header) != 64:
            raise AssertionError("ELF header must be 64 bytes")
        ep_out.write(elf_header, timeout=TIMEOUT_MS)

        phdr_request = read_packet(ep_in)
        command, length = packet_header(phdr_request)
        if command != READ_DATA64 or length < 32 or len(phdr_request) < 32:
            show_response(phdr_request, "After ELF header")
            return 0
        image_id, reserved, offset, requested = read_data64_fields(phdr_request)
        print(
            f"Program-header request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, offset, requested) != (IMAGE_ID, 64, 56):
            print("Unexpected PHDR request; stopping without sending PHDR bytes.")
            return 0

        # PT_LOAD, PF_R only; p_filesz=p_memsz=1. p_paddr is zero, but no
        # segment data is ever supplied, so the target cannot load this byte.
        phdr = struct.pack(
            "<IIQQQQQQ",
            1,      # PT_LOAD
            4,      # PF_R (not executable)
            120,    # p_offset, immediately after ELF header + one PHDR
            0,      # p_vaddr
            0,      # p_paddr
            1,      # p_filesz
            1,      # p_memsz
            1,      # p_align
        )
        if len(phdr) != 56:
            raise AssertionError("ELF64 program header must be 56 bytes")
        ep_out.write(phdr, timeout=TIMEOUT_MS)

        response = read_packet(ep_in)
        if show_response(response, "After PT_LOAD metadata"):
            print("Stopped here: no segment byte was sent.")
        else:
            print("Stopped here: no additional image bytes were sent.")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
