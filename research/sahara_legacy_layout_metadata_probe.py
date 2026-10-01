#!/usr/bin/env python3
"""Send only a legacy Qualcomm ELF's structural metadata to a Sahara PBL.

The probe supplies the ELF64 header and three PHDRs (header placeholder,
one-byte PT_LOAD, and legacy hash-segment placeholder). By default it
preserves the earlier metadata profile; --exec-consistent sets e_entry to the
PT_LOAD address and marks it PF_R|PF_X for a structural-consistency check. It
never supplies any segment or hash-table contents. It prints and stops on the
first subsequent READ_DATA request or END_IMAGE_TX response.

The PT_LOAD destination is an MSM8998-family L2-as-TCM address cited by the
upstream U-Boot Qualcomm SPL discussion. That map is not a verified Portal PBL
whitelist; this probe only asks the parser how it handles the metadata and
does not load a byte at that destination.
"""

from __future__ import annotations

import argparse
import struct
import sys

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

# Public MSM8998-family pre-DRAM candidates: L2-as-TCM at 0x14000000 or
# OCIMEM at 0x14680000. The supplied --load-address is metadata only.
DEFAULT_LOAD_ADDRESS = 0x14000000
LOAD_SIZE = 1
HASH_TABLE_SIZE = 72  # historical MBN header (40) + one SHA-256 digest (32)
HASH_SEGMENT_FILE_ALIGNMENT = 0x1000
ELF_HEADER_SIZE = 64
PHDR_SIZE = 56
PHDR_COUNT = 3
PHDRS_OFFSET = ELF_HEADER_SIZE
HEADER_PLACEHOLDER_SIZE = ELF_HEADER_SIZE + PHDR_COUNT * PHDR_SIZE
LOAD_OFFSET = HEADER_PLACEHOLDER_SIZE
# Qualcomm-derived mkmbn tooling uses a 0x1000 hash-segment alignment. The
# prior metadata probe declared p_align=0x1000 but placed p_offset immediately
# after the one-byte load segment (0xe9), which was incongruent with its aligned
# destination. Keep the test segment out of the PHDR area and align its file
# offset to match hash_dest; no bytes at this offset are sent by this probe.
HASH_OFFSET = (
    LOAD_OFFSET + LOAD_SIZE + HASH_SEGMENT_FILE_ALIGNMENT - 1
) & ~(HASH_SEGMENT_FILE_ALIGNMENT - 1)


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


def report(packet: bytes) -> None:
    command, length = packet_header(packet)
    if command == END_IMAGE_TX:
        raw = packet[:length].hex() if length <= len(packet) else packet.hex()
        status = struct.unpack_from("<I", packet, 12)[0] if length >= 16 else None
        print(f"END_IMAGE_TX status={status!r} raw={raw}")
        print("Stopped; no segment or hash bytes were sent.")
        return
    if command == READ_DATA64 and length >= 32 and len(packet) >= 32:
        image_id, reserved, offset, requested = read_data64_fields(packet)
        print(
            f"READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        print("Stopped at the first post-PHDR request; no requested bytes were sent.")
        return
    print(f"Unexpected packet raw={packet.hex()}; stopped without more data.")


def make_elf_header(entry_point: int) -> bytes:
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2, 183, 1,       # ET_EXEC, EM_AARCH64, ELF version
        entry_point,
        PHDRS_OFFSET,
        0, 0,
        ELF_HEADER_SIZE,
        PHDR_SIZE,
        PHDR_COUNT,
        0, 0, 0,
    )
    assert len(header) == ELF_HEADER_SIZE
    return header


def make_phdrs(load_address: int, executable: bool) -> tuple[bytes, int]:
    # Qualcomm-derived legacy MBN conventions: header-placeholder PT_NULL
    # (0x07000000), PT_LOAD, then hash PT_NULL (0x02200000).
    header_placeholder = struct.pack(
        "<IIQQQQQQ",
        0, 0x07000000, 0,
        0, 0,
        HEADER_PLACEHOLDER_SIZE,
        HEADER_PLACEHOLDER_SIZE,
        0x1000,
    )
    hash_dest = (load_address + LOAD_SIZE + 0xFFF) & ~0xFFF
    nonexec_load = struct.pack(
        "<IIQQQQQQ",
        1, 5 if executable else 4, LOAD_OFFSET,
        load_address, load_address,
        LOAD_SIZE,
        LOAD_SIZE,
        1,
    )
    hash_placeholder = struct.pack(
        "<IIQQQQQQ",
        0, 0x02200000, HASH_OFFSET,
        hash_dest, hash_dest,
        HASH_TABLE_SIZE,
        HASH_TABLE_SIZE,
        0x1000,
    )
    phdrs = header_placeholder + nonexec_load + hash_placeholder
    assert len(phdrs) == PHDR_COUNT * PHDR_SIZE
    return phdrs, hash_dest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--load-address",
        type=lambda value: int(value, 0),
        default=DEFAULT_LOAD_ADDRESS,
        help="candidate PT_LOAD p_vaddr/p_paddr; no segment bytes are sent",
    )
    parser.add_argument(
        "--exec-consistent",
        action="store_true",
        help="set e_entry=PT_LOAD address and mark PT_LOAD PF_R|PF_X",
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

        hello_resp = struct.pack(
            "<12I", HELLO_RESP, 0x30, version, version_min, 0, 0,
            0, 0, 0, 0, 0, 0,
        )
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)
        request = read_packet(ep_in)
        command, length = packet_header(request)
        if command != READ_DATA64 or length < 32 or len(request) < 32:
            report(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        print(
            f"Initial request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, offset, requested) != (IMAGE_ID, 0, ELF_HEADER_SIZE):
            print("Unexpected initial request; stopped without image bytes.")
            return 0

        entry_point = args.load_address if args.exec_consistent else 0
        ep_out.write(make_elf_header(entry_point), timeout=TIMEOUT_MS)
        request = read_packet(ep_in)
        if packet_header(request)[0] != READ_DATA64:
            report(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        print(
            f"PHDR request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, offset, requested) != (
            IMAGE_ID, PHDRS_OFFSET, PHDR_COUNT * PHDR_SIZE
        ):
            print("Unexpected PHDR request; stopped without PHDR bytes.")
            return 0

        phdrs, hash_dest = make_phdrs(args.load_address, args.exec_consistent)
        print(
            f"Sending {PHDR_COUNT} metadata-only PHDRs; e_entry=0x{entry_point:x}; "
            f"PT_LOAD destination=0x{args.load_address:x}, flags="
            f"{'PF_R|PF_X' if args.exec_consistent else 'PF_R'}, size={LOAD_SIZE}; "
            f"hash destination=0x{hash_dest:x}."
        )
        ep_out.write(phdrs, timeout=TIMEOUT_MS)
        report(read_packet(ep_in))
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
