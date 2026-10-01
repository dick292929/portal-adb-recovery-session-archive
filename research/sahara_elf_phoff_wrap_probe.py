#!/usr/bin/env python3
"""Check whether the Sahara ELF parser wraps an extreme program-header offset.

This sends one structured ELF64/AArch64 header with a program-header offset
near UINT64_MAX. It stops at the first request or error after that header; it
never sends the requested program-header bytes, an image body, a loader, or a
memory/storage command.

Run only after the Portal has been fully powered off and freshly entered EDL.
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

ELF_HEADER_SIZE = 64
PHDR_SIZE = 56
DEFAULT_PHDR_OFFSET = 0xFFFFFFFFFFFFFFF0


def read_packet(ep_in) -> bytes:
    packet = bytes(ep_in.read(READ_SIZE, timeout=TIMEOUT_MS))
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara packet ({len(packet)} bytes): {packet.hex()}")
    command, packet_len = struct.unpack_from("<II", packet)
    if packet_len < 8 or packet_len > len(packet):
        raise RuntimeError(
            f"invalid packet length 0x{packet_len:x} for {len(packet)} bytes: {packet.hex()}"
        )
    return packet[:packet_len]


def packet_header(packet: bytes) -> tuple[int, int]:
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara packet: {packet.hex()}")
    return struct.unpack_from("<II", packet)


def make_elf_header(phdr_offset: int, phdr_count: int) -> bytes:
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2, 183, 1,  # ET_EXEC, EM_AARCH64, ELF version
        0,           # entry point
        phdr_offset,
        0, 0,
        ELF_HEADER_SIZE,
        PHDR_SIZE,
        phdr_count,
        0, 0, 0,
    )
    if len(header) != ELF_HEADER_SIZE:
        raise AssertionError(f"unexpected ELF header length {len(header)}")
    return header


def report(packet: bytes, *, phdr_table_sent: bool = False) -> None:
    command, packet_len = packet_header(packet)
    if command == READ_DATA64 and packet_len >= 32 and len(packet) >= 32:
        image_id, reserved = struct.unpack_from("<II", packet, 8)
        offset, requested = struct.unpack_from("<QQ", packet, 16)
        print(
            f"READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if phdr_table_sent:
            print("Stopped at the next request; no bytes for it were sent.")
        else:
            print("Stopped at the request; no program-header bytes were sent.")
        return
    if command == END_IMAGE_TX and packet_len >= 16 and len(packet) >= 16:
        image_id, status = struct.unpack_from("<II", packet, 8)
        print(
            f"END_IMAGE_TX image_id={image_id} status=0x{status:x} "
            f"raw={packet[:packet_len].hex()}"
        )
        if phdr_table_sent:
            print("Stopped after the target response; no further bytes were sent.")
        else:
            print("Stopped; no program-header bytes were sent.")
        return
    print(f"Unexpected packet raw={packet.hex()}; stopped without more data.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="confirm full power-off followed by a fresh EDL entry",
    )
    parser.add_argument(
        "--phoff",
        type=lambda value: int(value, 0),
        default=DEFAULT_PHDR_OFFSET,
        help=(
            "ELF e_phoff value (default: wrap-boundary check); "
            "the probe never sends requested PHDR bytes"
        ),
    )
    parser.add_argument(
        "--phnum",
        type=int,
        default=1,
        help="ELF program-header count (default: 1)",
    )
    parser.add_argument(
        "--send-null-phdr-table",
        action="store_true",
        help=(
            "after the header, send only a bounded all-zero PT_NULL table "
            "if the requested offset and length match the supplied ELF fields"
        ),
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        parser.error("requires --confirm-fresh-edl-entry after a full off→EDL entry")
    if args.phnum < 1 or args.phnum > 64:
        parser.error("--phnum must be between 1 and 64")

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
        command, packet_len = packet_header(request)
        if command != READ_DATA64 or packet_len < 32 or len(request) < 32:
            report(request)
            return 0

        image_id, reserved = struct.unpack_from("<II", request, 8)
        offset, requested = struct.unpack_from("<QQ", request, 16)
        print(
            f"Initial request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, offset, requested) != (IMAGE_ID, 0, ELF_HEADER_SIZE):
            print("Unexpected initial request; stopped without image bytes.")
            return 0

        print(
            f"Sending one ELF header with e_phoff=0x{args.phoff:x}, "
            f"e_phentsize={PHDR_SIZE}, e_phnum={args.phnum}."
        )
        ep_out.write(make_elf_header(args.phoff, args.phnum), timeout=TIMEOUT_MS)
        table_request = read_packet(ep_in)
        command, packet_len = packet_header(table_request)
        if command != READ_DATA64 or packet_len < 32 or len(table_request) < 32:
            report(table_request)
            return 0

        image_id, reserved = struct.unpack_from("<II", table_request, 8)
        table_offset, table_length = struct.unpack_from("<QQ", table_request, 16)
        print(
            f"PHDR request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{table_offset:x} length=0x{table_length:x}"
        )
        if not args.send_null_phdr_table:
            report(table_request)
            return 0

        expected_offset = args.phoff & 0xFFFFFFFF
        expected_length = PHDR_SIZE * args.phnum
        if (image_id, table_offset, table_length) != (
            IMAGE_ID,
            expected_offset,
            expected_length,
        ):
            print("Request did not match the bounded PT_NULL-table expectation; stopped.")
            report(table_request)
            return 0

        print(
            f"Sending exactly {expected_length} zero bytes as {args.phnum} PT_NULL entries."
        )
        ep_out.write(bytes(expected_length), timeout=TIMEOUT_MS)
        report(read_packet(ep_in), phdr_table_sent=True)
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
