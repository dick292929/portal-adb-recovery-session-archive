#!/usr/bin/env python3
"""Send one standard 8-byte Sahara RESET_STATE_MACHINE packet and stop.

The Qualcomm-authored Sahara protocol documentation describes packet 0x13 as
a normal command header containing a 32-bit command ID and a 32-bit packet
length. This probe tests that wire form once; it does not repeat the reset
loop, read identity material, transfer an image, or issue memory/storage
commands.
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

HELLO = 0x01
HELLO_RESP = 0x02
CMD_READY = 0x0B
RESET_STATE_MACHINE = 0x13
COMMAND_MODE = 0x03
PACKET_SIZE = 0x30


def read_once(endpoint, size: int) -> bytes:
    return bytes(endpoint.read(size, timeout=TIMEOUT_MS))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required after a full power-off followed by a new EDL entry",
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        parser.error("requires --confirm-fresh-edl-entry after fresh EDL entry")

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("libusb backend unavailable; no device command sent", file=sys.stderr)
        return 2

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("05c6:9008 not present; no device command sent")
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
            print("Sahara bulk endpoints unavailable; no command sent", file=sys.stderr)
            return 4

        hello = read_once(ep_in, PACKET_SIZE)
        if len(hello) < 24:
            print(f"short initial packet ({len(hello)} bytes); stopped", file=sys.stderr)
            return 5
        fields = struct.unpack_from("<6I", hello)
        if fields[0] != HELLO or fields[1] != PACKET_SIZE:
            print(f"unexpected initial packet={hello[:32].hex()}; stopped", file=sys.stderr)
            return 6

        version, version_min = fields[2], fields[3]
        print(
            f"HELLO version={version} min={version_min} mode={fields[5]}; "
            "selecting command mode"
        )

        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            PACKET_SIZE,
            version,
            version_min,
            0,
            COMMAND_MODE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        written = ep_out.write(hello_resp, timeout=TIMEOUT_MS)
        if written != len(hello_resp):
            print(f"short HELLO_RESP write={written}/{len(hello_resp)}; stopped", file=sys.stderr)
            return 7

        ready = read_once(ep_in, 8)
        if len(ready) < 8 or struct.unpack_from("<I", ready)[0] != CMD_READY:
            print(f"unexpected CMD_READY response={ready[:32].hex()}; stopped", file=sys.stderr)
            return 8

        reset_packet = struct.pack("<II", RESET_STATE_MACHINE, 8)
        print(f"sending exactly one standard RESET_STATE_MACHINE packet: {reset_packet.hex()}")
        written = ep_out.write(reset_packet, timeout=TIMEOUT_MS)
        if written != len(reset_packet):
            print(f"short reset-packet write={written}/{len(reset_packet)}; no retry", file=sys.stderr)
            return 9

        response = read_once(ep_in, PACKET_SIZE)
        if len(response) < 8:
            print(f"short response ({len(response)} bytes); stopped", file=sys.stderr)
            return 10

        command, length = struct.unpack_from("<II", response)
        print(f"one response: command=0x{command:x} length=0x{length:x} received={len(response)} bytes")
        if command == HELLO and len(response) >= 24:
            post = struct.unpack_from("<6I", response)
            print(f"post-reset HELLO version={post[2]} min={post[3]} mode={post[5]}")
        else:
            print(f"response_prefix={response[:32].hex()}")
        print("Stopped after one packet; no retry or follow-up command sent.")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara timeout or error={exc}; stopped without retry", file=sys.stderr)
        return 11
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
