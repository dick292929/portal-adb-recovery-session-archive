#!/usr/bin/env python3
"""Bounded Sahara v3 HELLO compatibility probe for the Portal.

Reads one HELLO. Only when the target advertises Sahara v2/min1/PBL mode,
sends one HELLO_RESP claiming v3/min1 in command mode, reads one bounded
response, and stops. It sends no EXEC, reset, image, memory, or storage request.
"""

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
END_IMAGE_TRANSFER = 0x04
COMMAND_MODE = 0x03
MAX_RESPONSE = 0x8000


def read_exact(endpoint, length):
    data = bytearray()
    while len(data) < length:
        chunk = endpoint.read(length - len(data), timeout=TIMEOUT_MS)
        if not chunk:
            raise RuntimeError(f"short USB read: {len(data)}/{length}")
        data.extend(chunk)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="authorize sending the one v3 HELLO_RESP compatibility probe",
    )
    if not parser.parse_args().confirm_send:
        parser.error("requires --confirm-send")

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("ERROR: libusb backend unavailable; no packet sent", file=sys.stderr)
        return 2

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("No 05c6:9008 device visible; no packet sent")
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
            print("Sahara bulk endpoints unavailable; no packet sent")
            return 4

        hello = read_exact(ep_in, 0x30)
        fields = struct.unpack("<12I", hello)
        if fields[0] != HELLO or fields[1] != 0x30:
            print(f"Unexpected first packet {hello.hex()}; stopped before sending")
            return 5

        version, version_min, max_packet, mode = fields[2:6]
        print(
            f"HELLO version={version} min={version_min} "
            f"max_packet={max_packet} mode={mode}"
        )
        if (version, version_min, mode) != (2, 1, 0):
            print("Target is not the expected Sahara v2/min1/PBL profile; no packet sent")
            return 6

        response = struct.pack(
            "<12I",
            HELLO_RESP,
            0x30,
            3,  # Probe whether the PBL accepts a v3 host version despite advertising v2.
            1,
            0,
            COMMAND_MODE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ep_out.write(response, timeout=TIMEOUT_MS)
        print("Sent exactly one HELLO_RESP with version=3/min=1, command mode")

        first = bytes(ep_in.read(16, timeout=TIMEOUT_MS))
        if len(first) < 8:
            print(f"Short response ({len(first)} bytes) raw={first.hex()}; stopped")
            return 7
        command, length = struct.unpack_from("<II", first)
        if length < 8 or length > MAX_RESPONSE:
            print(f"Response header command=0x{command:x} invalid_length={length}; stopped")
            return 7
        packet = first[:length]
        if len(packet) < length:
            packet += read_exact(ep_in, length - len(packet))
        print(f"First response command=0x{command:x} length={length} raw={packet.hex()}")
        if command == CMD_READY:
            print("Command mode accepted; stopped before any client command")
        elif command == END_IMAGE_TRANSFER:
            if length == 16:
                _, _, image_id, status = struct.unpack("<4I", packet)
                status_name = {0x02: "PROTOCOL_MISMATCH"}.get(status, "unknown")
                print(
                    f"HELLO_RESP rejected: image_id={image_id} "
                    f"status=0x{status:x} ({status_name}); stopped"
                )
            else:
                print("HELLO_RESP rejected/ended; stopped without follow-up")
        else:
            print("Unexpected response; stopped without follow-up")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara probe ended: {exc}", file=sys.stderr)
        return 10
    except Exception as exc:
        print(f"Probe stopped: {exc}", file=sys.stderr)
        return 11
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
