#!/usr/bin/env python3
"""Send a source-shaped legacy Qualcomm ELF metadata prefix over Sahara.

This probe stops at the first request after the program-header table. It does
not send the hash-segment body, PT_LOAD body, a loader, or any storage command.
By default it selects image-transfer-pending mode (0), matching the earlier
Portal parser probes. ``--image-tx-complete`` selects mode (1) for a controlled
differential after the separate mode-1 gate requested image bytes.
The fixed PT_LOAD address is the previously tested MSM8998-family L2-as-TCM
candidate (0x14000000); that public SoC map is not a confirmed Portal PBL
whitelist.

Run only after a complete device power-off and a new EDL entry, and pass
--confirm-fresh-edl-entry to acknowledge that precondition.
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
IMAGE_TX_PENDING = 0
IMAGE_TX_COMPLETE = 1

LOAD_ADDRESS = 0x14000000  # Previously tested SoC-map candidate; not Portal-validated.
LOAD_SIZE = 1

ELF_HEADER_SIZE = 64
PHDR_SIZE = 56
PHDR_COUNT = 3
PHDRS_OFFSET = ELF_HEADER_SIZE
HEADER_PLACEHOLDER_SIZE = ELF_HEADER_SIZE + PHDR_COUNT * PHDR_SIZE

# Historical Qualcomm-derived MBNv5/SHA-256 builder parameters. pboot_gen_elf
# contributes entries for the ELF+PHDR header, the empty hash-segment entry,
# and the single non-empty PT_LOAD entry: three 32-byte digests.
MBN_HEADER_SIZE = 40
SHA256_SIZE = 32
HASH_TABLE_SIZE = PHDR_COUNT * SHA256_SIZE
SIGNATURE_SIZE = 256
ONE_ROOT_CERT_CHAIN_MAX_SIZE = 6 * 1024
HASH_SEGMENT_FILE_SIZE = (
    MBN_HEADER_SIZE + HASH_TABLE_SIZE + SIGNATURE_SIZE + ONE_ROOT_CERT_CHAIN_MAX_SIZE
)
PAGE_SIZE = 0x1000
HASH_OFFSET = PAGE_SIZE
HASH_DESTINATION = LOAD_ADDRESS + PAGE_SIZE
HASH_SEGMENT_MEMORY_SIZE = (
    (HASH_SEGMENT_FILE_SIZE + PAGE_SIZE - 1) // PAGE_SIZE
) * PAGE_SIZE
LOAD_OFFSET = HASH_OFFSET + HASH_SEGMENT_MEMORY_SIZE

MI_PBT_ELF_AMSS_NON_PAGED_RO_SEGMENT = 0x01200000
MI_PBT_ELF_PHDR_SEGMENT = 0x07000000
MI_PBT_ELF_HASH_SEGMENT = 0x02200000
PF_R_X = 0x5


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


def report_boundary(packet: bytes) -> None:
    command, length = packet_header(packet)
    if command == END_IMAGE_TX:
        raw = packet[:length].hex() if length <= len(packet) else packet.hex()
        status = struct.unpack_from("<I", packet, 12)[0] if length >= 16 else None
        print(f"END_IMAGE_TX status={status!r} raw={raw}")
        print("Stopped; no post-PHDR bytes were sent.")
        return
    if command == READ_DATA64 and length >= 32 and len(packet) >= 32:
        image_id, reserved, offset, requested = read_data64_fields(packet)
        print(
            f"READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        print("Stopped at the request; none of the requested bytes were sent.")
        return
    print(f"Unexpected packet raw={packet.hex()}; stopped without more data.")


def make_elf_header() -> bytes:
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2, 183, 1,  # ET_EXEC, EM_AARCH64, ELF version
        LOAD_ADDRESS,
        PHDRS_OFFSET,
        0, 0,
        ELF_HEADER_SIZE,
        PHDR_SIZE,
        PHDR_COUNT,
        0, 0, 0,
    )
    assert len(header) == ELF_HEADER_SIZE
    return header


def make_phdrs() -> bytes:
    # Match the output ordering in Qualcomm-derived pboot_gen_elf:
    # header+PHDR placeholder, hash segment, then original PT_LOAD.
    header_placeholder = struct.pack(
        "<IIQQQQQQ",
        0, MI_PBT_ELF_PHDR_SEGMENT, 0,
        0, 0,
        HEADER_PLACEHOLDER_SIZE,
        0,  # The reference builder leaves p_memsz at zero.
        0,
    )
    hash_segment = struct.pack(
        "<IIQQQQQQ",
        0, MI_PBT_ELF_HASH_SEGMENT, HASH_OFFSET,
        HASH_DESTINATION, HASH_DESTINATION,
        HASH_SEGMENT_FILE_SIZE,
        HASH_SEGMENT_MEMORY_SIZE,
        PAGE_SIZE,
    )
    # Qualcomm uses p_flags[27:20] for its segment class and keeps the ELF
    # permission bits in the low three bits. This is a source-backed AMSS,
    # non-paged, read-only class combined with PF_R|PF_X.
    load_segment = struct.pack(
        "<IIQQQQQQ",
        1,
        MI_PBT_ELF_AMSS_NON_PAGED_RO_SEGMENT | PF_R_X,
        LOAD_OFFSET,
        LOAD_ADDRESS,
        LOAD_ADDRESS,
        LOAD_SIZE,
        LOAD_SIZE,
        1,
    )
    phdrs = header_placeholder + hash_segment + load_segment
    assert len(phdrs) == PHDR_COUNT * PHDR_SIZE
    return phdrs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image-tx-complete",
        action="store_true",
        help="select HELLO_RESP mode 1 instead of the prior mode-0 baseline",
    )
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required: confirm a full power-off followed by a new EDL entry",
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
        response_mode = IMAGE_TX_COMPLETE if args.image_tx_complete else IMAGE_TX_PENDING
        print(
            f"HELLO version={version} min={version_min} "
            f"max_cmd_len={fields[4]} mode={fields[5]}; "
            f"selecting HELLO_RESP mode={response_mode}"
        )

        hello_resp = struct.pack(
            "<12I", HELLO_RESP, 0x30, version, version_min, 0, response_mode,
            0, 0, 0, 0, 0, 0,
        )
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)
        request = read_packet(ep_in)
        command, length = packet_header(request)
        if command != READ_DATA64 or length < 32 or len(request) < 32:
            report_boundary(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        print(
            f"Initial request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, reserved, offset, requested) != (
            IMAGE_ID, 0, 0, ELF_HEADER_SIZE
        ):
            print("Unexpected initial request; stopped without image bytes.")
            return 0

        ep_out.write(make_elf_header(), timeout=TIMEOUT_MS)
        request = read_packet(ep_in)
        command, length = packet_header(request)
        if command != READ_DATA64 or length != 32 or len(request) < 32:
            report_boundary(request)
            return 0
        image_id, reserved, offset, requested = read_data64_fields(request)
        print(
            f"PHDR request: image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}"
        )
        if (image_id, reserved, offset, requested) != (
            IMAGE_ID, 0, PHDRS_OFFSET, PHDR_COUNT * PHDR_SIZE
        ):
            print("Unexpected PHDR request; stopped without PHDR bytes.")
            return 0

        print(
            f"Sending {PHDR_COUNT} corrected metadata PHDRs only; "
            f"PT_LOAD=0x{LOAD_ADDRESS:x}, hash=0x{HASH_DESTINATION:x}, "
            f"hash_file_size=0x{HASH_SEGMENT_FILE_SIZE:x}, "
            f"hash_mem_size=0x{HASH_SEGMENT_MEMORY_SIZE:x}."
        )
        ep_out.write(make_phdrs(), timeout=TIMEOUT_MS)
        report_boundary(read_packet(ep_in))
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
