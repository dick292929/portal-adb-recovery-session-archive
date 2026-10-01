#!/usr/bin/env python3
"""One-shot check of the four-byte Sahara 0x13 form shown in Qualcomm slides.

Requires a fresh EDL entry. This performs the normal v2 HELLO/CMD_READY
handshake, sends exactly one 4-byte reset-state-machine candidate
(13 9a 9a 9a), then reads one response and stops. It does not loop, read
identity secrets, send an image, or issue storage commands.
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
COMMAND_MODE = 0x03

RESET_STATE_MACHINE_WORD = bytes.fromhex("13 9a 9a 9a")


def read_exact_packet(endpoint, size: int) -> bytes:
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

        hello = read_exact_packet(ep_in, 0x30)
        if len(hello) < 0x30:
            print(f"short initial packet ({len(hello)} bytes); stopped", file=sys.stderr)
            return 5
        fields = struct.unpack_from("<12I", hello)
        if fields[0] != HELLO or fields[1] != 0x30:
            print(f"unexpected initial packet={hello.hex()}; stopped", file=sys.stderr)
            return 6

        version, version_min, max_packet, mode = fields[2:6]
        if version != 2 or version_min != 1:
            print(
                f"unexpected HELLO version={version} min={version_min}; stopped",
                file=sys.stderr,
            )
            return 7
        print(
            f"HELLO version={version} min={version_min} max_packet={max_packet} "
            f"mode={mode}; selecting command mode"
        )

        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            0x30,
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
            print(
                f"short HELLO_RESP write={written}/{len(hello_resp)}; stopped",
                file=sys.stderr,
            )
            return 8

        ready = read_exact_packet(ep_in, 0x08)
        if len(ready) < 8 or struct.unpack_from("<I", ready)[0] != CMD_READY:
            print(f"unexpected CMD_READY response={ready.hex()}; stopped", file=sys.stderr)
            return 9

        print("Sending exactly one 4-byte reset-state-machine candidate: 13 9a 9a 9a")
        written = ep_out.write(RESET_STATE_MACHINE_WORD, timeout=TIMEOUT_MS)
        if written != len(RESET_STATE_MACHINE_WORD):
            print(
                f"short candidate write={written}/{len(RESET_STATE_MACHINE_WORD)}; "
                "no retry",
                file=sys.stderr,
            )
            return 10

        response = read_exact_packet(ep_in, 0x30)
        if len(response) >= 8:
            command, length = struct.unpack_from("<II", response)
            print(
                f"one response: command=0x{command:x} length=0x{length:x} "
                f"received={len(response)} bytes"
            )
            if command == HELLO and len(response) >= 24:
                fields = struct.unpack_from("<6I", response)
                print(
                    f"post-command HELLO version={fields[2]} min={fields[3]} "
                    f"max_packet={fields[4]} mode={fields[5]}"
                )
        else:
            print(f"short response={response.hex()}; stopped")
        print("Stopped after one candidate; no retry or follow-up command sent.")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara timeout or error={exc}; stopped without retry", file=sys.stderr)
        return 11
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
