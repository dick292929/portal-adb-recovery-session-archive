#!/usr/bin/env python3
"""Try Sahara's command-mode SWITCH_MODE path to memory-debug mode.

This sends one top-level SWITCH_MODE request after a normal command-mode
handshake. If the target announces a memory table, it reads only that bounded
table (never any listed memory region). No reset, image, loader, payload, or
storage-write command is sent. The target may remain in memory-debug mode;
power-cycle it after the probe.
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
HELLO = 0x01
HELLO_RESP = 0x02
END_IMAGE_TRANSFER = 0x04
MEMORY_DEBUG = 0x09
MEMORY_READ = 0x0A
CMD_READY = 0x0B
SWITCH_MODE = 0x0C
MEMORY_DEBUG64 = 0x10
MEMORY_READ64 = 0x11
MODE_MEMORY_DEBUG = 0x02
MODE_COMMAND = 0x03
MAX_TABLE_BYTES = 0x8000
ENTRY32_SIZE = 52
ENTRY64_SIZE = 64
TIMEOUT_MS = 3000


def read_packet(ep_in, timeout_ms: int = TIMEOUT_MS) -> bytes:
    packet = bytes(ep_in.read(0x1000, timeout=timeout_ms))
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara packet: {packet.hex()}")
    command, packet_len = struct.unpack_from("<II", packet)
    if packet_len < 8 or packet_len > len(packet):
        raise RuntimeError(
            f"invalid packet length 0x{packet_len:x} for {len(packet)} received bytes"
        )
    return packet[:packet_len]


def read_exact(ep_in, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        result.extend(bytes(ep_in.read(size - len(result), timeout=TIMEOUT_MS)))
    return bytes(result)


def print_memory_table(data: bytes, is_64bit: bool) -> None:
    entry_size = ENTRY64_SIZE if is_64bit else ENTRY32_SIZE
    if len(data) % entry_size:
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
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="confirm the device was fully powered off and freshly placed in EDL",
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        print(
            "Refusing: first fully power off the Portal, freshly enter EDL, "
            "then pass --confirm-fresh-edl-entry.",
            file=sys.stderr,
        )
        return 2

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("ERROR: libusb backend unavailable", file=sys.stderr)
        return 3

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("No Qualcomm EDL device (05c6:9008) is currently visible.")
        return 4

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
        if ep_out is None or ep_in is None:
            print("ERROR: Sahara bulk endpoints were not found", file=sys.stderr)
            return 5

        hello = read_packet(ep_in)
        if len(hello) < 0x30:
            print(f"Unexpected short HELLO: {hello.hex()}")
            return 6
        fields = struct.unpack_from("<12I", hello)
        command, packet_len, version, version_min, max_packet, current_mode = fields[:6]
        if command != HELLO or packet_len != 0x30:
            print(f"Unexpected initial packet: {hello.hex()}")
            return 7
        print(
            f"HELLO version={version} min={version_min} max_packet={max_packet} "
            f"mode={current_mode}; selecting command mode"
        )

        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            0x30,
            version,
            version_min,
            0,
            MODE_COMMAND,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)
        ready = read_packet(ep_in)
        ready_cmd = struct.unpack_from("<I", ready)[0]
        if ready_cmd != CMD_READY:
            print(
                f"Command mode not ready: command=0x{ready_cmd:02x} "
                f"raw={ready.hex()}"
            )
            return 0

        print("Command mode ready; sending one SWITCH_MODE request to memory-debug mode")
        ep_out.write(
            struct.pack("<III", SWITCH_MODE, 12, MODE_MEMORY_DEBUG),
            timeout=TIMEOUT_MS,
        )
        response = read_packet(ep_in)
        response_cmd = struct.unpack_from("<I", response)[0]

        if response_cmd == END_IMAGE_TRANSFER:
            print(f"SWITCH_MODE rejected/ended: raw={response.hex()}")
            return 0

        if response_cmd == HELLO:
            if len(response) < 0x30:
                print(f"Short HELLO after SWITCH_MODE: {response.hex()}")
                return 0
            switched = struct.unpack_from("<12I", response)
            _, _, new_version, new_min, new_max_packet, new_mode = switched[:6]
            print(
                f"Post-switch HELLO version={new_version} min={new_min} "
                f"max_packet={new_max_packet} mode={new_mode}"
            )
            if new_mode != MODE_MEMORY_DEBUG:
                print("Target did not report memory-debug mode; stopping.")
                return 0
            ep_out.write(
                struct.pack(
                    "<12I",
                    HELLO_RESP,
                    0x30,
                    new_version,
                    new_min,
                    0,
                    MODE_MEMORY_DEBUG,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
                timeout=TIMEOUT_MS,
            )
            response = read_packet(ep_in)
            response_cmd = struct.unpack_from("<I", response)[0]

        is_64bit = response_cmd == MEMORY_DEBUG64
        if response_cmd not in (MEMORY_DEBUG, MEMORY_DEBUG64):
            print(f"No memory-debug table announcement: raw={response.hex()}")
            return 0

        minimum_len = 0x18 if is_64bit else 0x10
        if len(response) < minimum_len:
            print(f"Malformed memory-debug announcement: {response.hex()}")
            return 0
        if is_64bit:
            table_addr, table_len = struct.unpack_from("<QQ", response, 8)
        else:
            table_addr, table_len = struct.unpack_from("<II", response, 8)
        entry_size = ENTRY64_SIZE if is_64bit else ENTRY32_SIZE
        print(
            f"{64 if is_64bit else 32}-bit table announcement: "
            f"address=0x{table_addr:x} length=0x{table_len:x}"
        )
        if (
            table_len == 0
            or table_len > MAX_TABLE_BYTES
            or table_len % entry_size
        ):
            print(
                "Refusing table read: length is zero, over the 0x8000-byte cap, "
                "or not a whole number of entries."
            )
            return 0

        if is_64bit:
            request = struct.pack("<IIQQ", MEMORY_READ64, 0x18, table_addr, table_len)
        else:
            request = struct.pack("<IIII", MEMORY_READ, 0x10, table_addr, table_len)
        ep_out.write(request, timeout=TIMEOUT_MS)
        table = read_exact(ep_in, table_len)
        print(f"Read only {len(table)} bytes of memory-table metadata:")
        print_memory_table(table, is_64bit)
        print(
            "Stopped after the table; no listed region was read. "
            "Power-cycle the Portal to leave memory-debug mode."
        )
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara request ended with: {exc}", file=sys.stderr)
        return 8
    except RuntimeError as exc:
        print(f"Protocol error: {exc}", file=sys.stderr)
        return 9
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
