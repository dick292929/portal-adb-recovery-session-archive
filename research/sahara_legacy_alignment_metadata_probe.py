#!/usr/bin/env python3
"""Metadata-only Sahara parser oracle probes.

Requires a full power-off followed by a new EDL entry. Sends the standard
HELLO_RESP, one 64-byte ELF header, and exactly one three-PHDR metadata table.
By default it uses PT_LOAD p_align=0x1000. The optional
--clear-hash-segment-flag control changes only the hash PHDR p_flags to zero.
It stops at the first response after the PHDR table and never sends hash or
PT_LOAD contents. These checks parser responses only; they are not an exploit.
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
IMAGE_TX_COMPLETE = 1

ELF_HEADER_SIZE = 64
PHDR_SIZE = 56
PHDR_COUNT = 3
PHDRS_OFFSET = ELF_HEADER_SIZE

# Baseline source-derived metadata values. The standard run uses the tested
# PT_LOAD.p_align=0x1000 value; the optional control changes only hash p_flags.
LOAD_ADDRESS = 0x14000000
LOAD_SIZE = 1
PAGE_SIZE = 0x1000
MBN_HEADER_SIZE = 40
HASH_TABLE_SIZE = 3 * 32
SIGNATURE_SIZE = 256
ONE_ROOT_CERT_CHAIN_MAX_SIZE = 6 * 1024
HASH_TABLE_AND_SIGNATURE_SIZE = (
    HASH_TABLE_SIZE + SIGNATURE_SIZE + ONE_ROOT_CERT_CHAIN_MAX_SIZE
)
HASH_FILE_SIZE = MBN_HEADER_SIZE + HASH_TABLE_AND_SIGNATURE_SIZE
HASH_MEMORY_SIZE = 0x2000
HASH_OFFSET = PAGE_SIZE
HASH_ADDRESS = LOAD_ADDRESS + PAGE_SIZE
LOAD_OFFSET = HASH_OFFSET + HASH_MEMORY_SIZE

MI_PBT_ELF_AMSS_NON_PAGED_RO_SEGMENT = 0x01200000
MI_PBT_ELF_PHDR_SEGMENT = 0x07000000
MI_PBT_ELF_HASH_SEGMENT = 0x02200000
PF_R_X = 0x5


def read_packet(ep_in) -> bytes:
    return bytes(ep_in.read(READ_SIZE, timeout=TIMEOUT_MS))


def write_exact(ep_out, payload: bytes, label: str) -> None:
    written = ep_out.write(payload, timeout=TIMEOUT_MS)
    if written != len(payload):
        raise RuntimeError(
            f"short USB OUT write for {label}: {written}/{len(payload)} bytes"
        )
    print(f"USB OUT {label}: {written}/{len(payload)} bytes")


def packet_header(packet: bytes) -> tuple[int, int]:
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara packet ({len(packet)} bytes): {packet.hex()}")
    return struct.unpack_from("<II", packet)


def read_data64_fields(packet: bytes) -> tuple[int, int, int, int]:
    command, length = packet_header(packet)
    if command != READ_DATA64 or length != 32 or len(packet) < 32:
        raise RuntimeError(f"not a complete READ_DATA64 packet: {packet.hex()}")
    return struct.unpack_from("<IIQQ", packet, 8)


def make_elf_header(load_address: int) -> bytes:
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2, 183, 1,  # ET_EXEC, EM_AARCH64, ELF version
        load_address,
        PHDRS_OFFSET,
        0, 0,
        ELF_HEADER_SIZE,
        PHDR_SIZE,
        PHDR_COUNT,
        0, 0, 0,
    )
    assert len(header) == ELF_HEADER_SIZE
    return header


def make_phdrs(
    load_address: int,
    hash_address: int,
    hash_segment_flags: int = MI_PBT_ELF_HASH_SEGMENT,
) -> bytes:
    header_placeholder_size = ELF_HEADER_SIZE + PHDR_COUNT * PHDR_SIZE
    header_placeholder = struct.pack(
        "<IIQQQQQQ",
        0, MI_PBT_ELF_PHDR_SEGMENT, 0,
        0, 0,
        header_placeholder_size,
        0,
        0,
    )
    hash_segment = struct.pack(
        "<IIQQQQQQ",
        0, hash_segment_flags, HASH_OFFSET,
        hash_address, hash_address,
        HASH_FILE_SIZE,
        HASH_MEMORY_SIZE,
        PAGE_SIZE,
    )
    load_segment = struct.pack(
        "<IIQQQQQQ",
        1,
        MI_PBT_ELF_AMSS_NON_PAGED_RO_SEGMENT | PF_R_X,
        LOAD_OFFSET,
        load_address,
        load_address,
        LOAD_SIZE,
        LOAD_SIZE,
        PAGE_SIZE,
    )
    phdrs = header_placeholder + hash_segment + load_segment
    assert len(phdrs) == PHDR_COUNT * PHDR_SIZE
    return phdrs


def report_boundary(packet: bytes) -> None:
    command, length = packet_header(packet)
    if command == END_IMAGE_TX and length >= 16 and len(packet) >= 16:
        image_id, status = struct.unpack_from("<II", packet, 8)
        raw = packet[:length].hex() if length <= len(packet) else packet.hex()
        print(f"END_IMAGE_TX image_id={image_id} status=0x{status:x} raw={raw}")
        print("Stopped; no image-body bytes were sent.")
        return
    if command == READ_DATA64 and length == 32 and len(packet) >= 32:
        image_id, reserved, offset, requested = read_data64_fields(packet)
        print(
            f"READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        print("Stopped at this request; none of the requested bytes were sent.")
        return
    print(f"Unexpected response raw={packet.hex()}; stopped without more data.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required: confirm a full power-off followed by a new EDL entry",
    )
    parser.add_argument(
        "--clear-hash-segment-flag",
        action="store_true",
        help="one-field parser control: set only hash PHDR p_flags to zero",
    )
    parser.add_argument(
        "--load-address",
        type=lambda value: int(value, 0),
        default=LOAD_ADDRESS,
        help=(
            "PT_LOAD p_paddr/p_vaddr (default: the previously tested candidate); "
            "use only a source-justified address"
        ),
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        parser.error("requires --confirm-fresh-edl-entry after a full off→EDL entry")

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
        load_address = args.load_address
        hash_address = load_address + PAGE_SIZE
        print(
            f"HELLO version={version} min={version_min}; "
            "selecting IMAGE_TX_COMPLETE mode=1"
        )
        write_exact(
            ep_out,
            struct.pack(
                "<12I", HELLO_RESP, 0x30, version, version_min, 0,
                IMAGE_TX_COMPLETE, 0, 0, 0, 0, 0, 0,
            ),
            "HELLO_RESP",
        )

        request = read_packet(ep_in)
        if packet_header(request)[0] != READ_DATA64:
            report_boundary(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        if (image_id, reserved, offset, requested) != (IMAGE_ID, 0, 0, ELF_HEADER_SIZE):
            print(
                f"Unexpected initial READ_DATA64 image_id={image_id} "
                f"reserved=0x{reserved:x} offset=0x{offset:x} length=0x{requested:x}; stopped."
            )
            return 0
        write_exact(ep_out, make_elf_header(load_address), "ELF header")

        request = read_packet(ep_in)
        if packet_header(request)[0] != READ_DATA64:
            report_boundary(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        if (image_id, reserved, offset, requested) != (
            IMAGE_ID, 0, PHDRS_OFFSET, PHDR_COUNT * PHDR_SIZE
        ):
            print(
                f"Unexpected PHDR READ_DATA64 image_id={image_id} "
                f"reserved=0x{reserved:x} offset=0x{offset:x} length=0x{requested:x}; stopped."
            )
            return 0

        hash_segment_flags = 0 if args.clear_hash_segment_flag else MI_PBT_ELF_HASH_SEGMENT
        if args.clear_hash_segment_flag:
            print(
                "Sending one-field hash-marker negative control: "
                f"hash_PHDR.p_flags=0x{hash_segment_flags:x}; other fields match "
                "the selected load-address layout."
            )
        else:
            print(
                "Sending metadata-only PHDR layout: "
                f"PT_LOAD.p_align=0x{PAGE_SIZE:x}; "
                f"PT_LOAD=0x{load_address:x}, hash=0x{hash_address:x}, "
                f"hash_file_size=0x{HASH_FILE_SIZE:x}."
            )
        write_exact(
            ep_out,
            make_phdrs(load_address, hash_address, hash_segment_flags),
            "PHDR table",
        )
        report_boundary(read_packet(ep_in))
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}; stopped without retry.", file=sys.stderr)
        return 8
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended: {exc}; stopped without retry.", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
