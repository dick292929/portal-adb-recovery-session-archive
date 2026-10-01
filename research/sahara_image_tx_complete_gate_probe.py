#!/usr/bin/env python3
"""Probe the Portal's Sahara image-transfer-complete handshake once.

This checks whether a fresh PBL session accepts HELLO_RESP mode 1, the mode
used by the public CVE-2021-30327 client before its exploit-image upload. The
probe reads and reports only the target's first response. If the target asks
for image data, it does not send any bytes.
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
MAX_RESPONSE = 0x30

HELLO = 0x01
HELLO_RESP = 0x02
READ_DATA = 0x03
END_IMAGE_TRANSFER = 0x04
CMD_READY = 0x0B
READ_DATA64 = 0x12

SAHARA_V2 = 0x02
IMAGE_TX_PENDING = 0x00
IMAGE_TX_COMPLETE = 0x01


def packet_header(packet):
    if len(packet) < 8:
        raise RuntimeError(f"short Sahara response ({len(packet)} bytes)")
    return struct.unpack_from("<II", packet)


def report_first_response(packet):
    command, length = packet_header(packet)
    if length < 8 or length > len(packet):
        print(
            f"Unexpected first response: command=0x{command:x} "
            f"declared_len={length} received_len={len(packet)}; stopped."
        )
        return

    if command == READ_DATA and length == 20:
        image_id, offset, requested = struct.unpack_from("<III", packet, 8)
        print(
            f"READ_DATA image_id={image_id} offset=0x{offset:x} "
            f"length=0x{requested:x}; stopped without sending image bytes."
        )
        return

    if command == READ_DATA64 and length == 32:
        image_id, reserved = struct.unpack_from("<II", packet, 8)
        offset, requested = struct.unpack_from("<QQ", packet, 16)
        print(
            f"READ_DATA64 image_id={image_id} reserved=0x{reserved:x} "
            f"offset=0x{offset:x} length=0x{requested:x}; "
            "stopped without sending image bytes."
        )
        return

    if command == END_IMAGE_TRANSFER and length == 16:
        image_id, status = struct.unpack_from("<II", packet, 8)
        print(
            "HELLO_RESP mode=1 rejected: "
            f"END_IMAGE_TRANSFER image_id={image_id} status=0x{status:x}; stopped."
        )
        return

    if command == CMD_READY and length == 8:
        print("CMD_READY received after HELLO_RESP mode=1; stopped without a client command.")
        return

    print(
        f"Unexpected first response: command=0x{command:x} "
        f"declared_len={length}; stopped without further traffic."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required: confirm full power-off followed by a fresh EDL entry",
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        parser.error("requires --confirm-fresh-edl-entry after a full off→EDL entry")

    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        print("ERROR: libusb backend unavailable; no device command sent", file=sys.stderr)
        return 2

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        print("No Qualcomm EDL device (05c6:9008) is visible; no command sent.")
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
            print("ERROR: Sahara bulk endpoints unavailable; no command sent", file=sys.stderr)
            return 4

        hello = bytes(ep_in.read(MAX_RESPONSE, timeout=TIMEOUT_MS))
        if len(hello) < MAX_RESPONSE:
            print(
                f"Unexpected short initial HELLO ({len(hello)} of 48 bytes); "
                "stopped without response."
            )
            return 5

        fields = struct.unpack_from("<12I", hello)
        if fields[0] != HELLO or fields[1] != MAX_RESPONSE:
            print("Unexpected initial Sahara packet; stopped without sending a response.")
            return 6

        version, version_min, max_packet, mode = fields[2:6]
        if version != SAHARA_V2 or version_min > SAHARA_V2:
            print(
                f"Unexpected Sahara protocol version={version} min={version_min}; "
                "stopped without response."
            )
            return 7
        if max_packet < MAX_RESPONSE or mode != IMAGE_TX_PENDING:
            print(
                f"Unexpected initial Sahara parameters: max_packet={max_packet} "
                f"mode={mode}; stopped without response."
            )
            return 8

        print(
            "HELLO v2 received; sending one HELLO_RESP selecting "
            "IMAGE_TX_COMPLETE mode (1)."
        )
        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            MAX_RESPONSE,
            version,
            version_min,
            0,
            IMAGE_TX_COMPLETE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)

        first_response = bytes(ep_in.read(MAX_RESPONSE, timeout=TIMEOUT_MS))
        report_first_response(first_response)
        print("Probe ended after the first response; no image data or reset command was sent.")
        return 0
    except usb.core.USBTimeoutError:
        print("Timed out waiting for the first response; stopped without retry.", file=sys.stderr)
        return 9
    except usb.core.USBError as exc:
        print(f"USB/Sahara probe stopped: {exc}; no retry sent.", file=sys.stderr)
        return 10
    except RuntimeError as exc:
        print(f"Sahara probe stopped: {exc}; no retry sent.", file=sys.stderr)
        return 11
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
