#!/usr/bin/env python3
"""Read only the Sahara memory-debug table from a Qualcomm EDL target.

The script does not read any listed memory region, issue Sahara reset/state
machine reset, send a loader or payload, or write device storage. It leaves the
device in memory-debug mode; power-cycle it to return to normal boot.
"""

from __future__ import annotations

import argparse
import struct
import sys

import usb.core
import usb.util
import usb.backend.libusb1


VID = 0x05C6
PID = 0x9008
HELLO = 0x01
HELLO_RESP = 0x02
END_IMAGE_TRANSFER = 0x04
MEMORY_DEBUG = 0x09
MEMORY_DEBUG64 = 0x10
MEMORY_READ = 0x0A
MEMORY_READ64 = 0x11
MODE_MEMORY_DEBUG = 0x02
MAX_TABLE_BYTES = 0x8000
ENTRY32_SIZE = 52
ENTRY64_SIZE = 64


def read_exact(ep_in, size: int, timeout_ms: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = bytes(ep_in.read(size - len(result), timeout=timeout_ms))
        if not chunk:
            raise RuntimeError(f"short raw memory-table transfer ({len(result)}/{size})")
        result.extend(chunk)
    return bytes(result)


def print_table(data: bytes, is_64bit: bool) -> None:
    entry_size = ENTRY64_SIZE if is_64bit else ENTRY32_SIZE
    if not data or len(data) % entry_size:
        raise RuntimeError(
            f"memory table length {len(data)} is not a multiple of {entry_size}"
        )

    for index in range(len(data) // entry_size):
        entry = data[index * entry_size : (index + 1) * entry_size]
        if is_64bit:
            kind, address, length = struct.unpack_from("<QQQ", entry)
            name_offset = 24
        else:
            kind, address, length = struct.unpack_from("<III", entry)
            name_offset = 12
        name = entry[name_offset : name_offset + 20].split(b"\0", 1)[0]
        filename = entry[name_offset + 20 : name_offset + 40].split(b"\0", 1)[0]
        print(
            f"region[{index}] type=0x{kind:x} address=0x{address:x} "
            f"length=0x{length:x} name={name.decode(errors='replace')!r} "
            f"file={filename.decode(errors='replace')!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=2500)
    args = parser.parse_args()

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("ERROR: libusb backend unavailable", file=sys.stderr)
        return 2

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("No Qualcomm EDL device (05c6:9008) is currently visible.")
        return 3

    try:
        try:
            dev.set_configuration()
        except usb.core.USBError:
            # It may already be configured; endpoint discovery below is decisive.
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
        if ep_out is None or ep_in is None:
            print("ERROR: Sahara bulk endpoints were not found", file=sys.stderr)
            return 4

        hello = bytes(ep_in.read(0x1000, timeout=args.timeout_ms))
        if len(hello) < 0x30:
            print(f"Unexpected short initial packet ({len(hello)} bytes): {hello.hex()}")
            return 5

        fields = struct.unpack_from("<12I", hello)
        command, packet_len, version, version_min = fields[:4]
        if command != HELLO or packet_len != 0x30:
            print(
                "Unexpected initial Sahara packet: "
                f"command=0x{command:x}, declared_length=0x{packet_len:x}, "
                f"received={len(hello)} bytes, raw={hello[:0x30].hex()}"
            )
            return 6

        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            0x30,
            version,
            version_min,
            0,  # status
            MODE_MEMORY_DEBUG,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ep_out.write(hello_resp, timeout=args.timeout_ms)
        response = bytes(ep_in.read(0x1000, timeout=args.timeout_ms))

        if len(response) < 8:
            print(f"Short response after memory-debug request: {response.hex()}")
            return 7

        command, packet_len = struct.unpack_from("<II", response)
        print(
            f"HELLO version={version} min={version_min}; "
            f"response command=0x{command:02x}, declared_length=0x{packet_len:x}, "
            f"received={len(response)} bytes"
        )

        is_64bit = command == MEMORY_DEBUG64
        if command in (MEMORY_DEBUG, MEMORY_DEBUG64):
            minimum_packet = 0x18 if is_64bit else 0x10
            if packet_len < minimum_packet or len(response) < minimum_packet:
                print(f"Malformed memory-debug announcement: {response.hex()}")
                return 9
            if is_64bit:
                table_addr, table_len = struct.unpack_from("<QQ", response, 8)
            else:
                table_addr, table_len = struct.unpack_from("<II", response, 8)

            print(
                f"{64 if is_64bit else 32}-bit memory-debug table: "
                f"address=0x{table_addr:x}, length=0x{table_len:x}"
            )
            if table_len == 0 or table_len > MAX_TABLE_BYTES:
                print(
                    f"Refusing table length outside the read-only probe limit "
                    f"(1..0x{MAX_TABLE_BYTES:x} bytes)."
                )
                return 10

            if is_64bit:
                request = struct.pack(
                    "<IIQQ", MEMORY_READ64, 0x18, table_addr, table_len
                )
            else:
                request = struct.pack(
                    "<IIII", MEMORY_READ, 0x10, table_addr, table_len
                )
            ep_out.write(request, timeout=args.timeout_ms)
            table = read_exact(ep_in, table_len, args.timeout_ms)
            print(f"Read {len(table)} table bytes. Listed regions (none were read):")
            print_table(table, is_64bit)
            print(
                "Stopped after the table. The device remains in Sahara memory-debug "
                "mode; power-cycle it to boot normally."
            )
            return 0
        if command == END_IMAGE_TRANSFER:
            print(f"Target declined/ended the request; raw={response[:packet_len].hex()}")
            return 0

        print(f"No memory-debug table announcement; raw={response[:packet_len].hex()}")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 8
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
