#!/usr/bin/env python3
"""Read Sahara EXEC SERIAL_NUM_READ once from a freshly entered EDL device.

The returned 32-bit serial is intentionally never printed, logged, or saved.
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
END_IMAGE_TRANSFER = 0x04
CMD_READY = 0x0B
CMD_EXEC = 0x0D
CMD_EXEC_RESP = 0x0E
CMD_EXEC_DATA = 0x0F
COMMAND_MODE = 0x03
SERIAL_NUM_READ = 0x01

SAHARA_V2 = 0x02
SAHARA_V2_MIN = 0x01
SERIAL_RESPONSE_BYTES = 4


def read_exact(endpoint, length):
    out = bytearray()
    while len(out) < length:
        chunk = endpoint.read(length - len(out), timeout=TIMEOUT_MS)
        if not chunk:
            raise RuntimeError(f"short USB read: got {len(out)} of {length} bytes")
        out.extend(chunk)
    return bytes(out)


def packet_header(data):
    if len(data) < 8:
        raise RuntimeError("short Sahara packet header")
    return struct.unpack_from("<II", data)


def read_end_image_transfer(ep_in, first_eight):
    response = first_eight + read_exact(ep_in, 8)
    _, length, image_id, status = struct.unpack("<4I", response)
    if length != 16:
        print("Unexpected short END_IMAGE_TRANSFER response; stopped.")
        return
    print(
        "Sahara command-mode entry rejected: "
        f"image_id={image_id} status=0x{status:x}; stopped without retry"
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

        hello = read_exact(ep_in, 0x30)
        fields = struct.unpack("<12I", hello)
        if fields[0] != HELLO or fields[1] != 0x30:
            print("Unexpected initial Sahara packet; stopped without sending a command.")
            return 5

        version, version_min, max_packet, mode = fields[2], fields[3], fields[4], fields[5]
        if version != SAHARA_V2 or version_min > SAHARA_V2 or max_packet < 0x30:
            print(
                "Unexpected Sahara protocol parameters; "
                "expected v2 with a valid packet size; stopped without response."
            )
            return 6
        if mode != 0:
            print(f"Unexpected initial Sahara mode={mode}; stopped without response.")
            return 7

        print("HELLO v2 received; entering command mode for one SERIAL_NUM_READ query.")
        hello_resp = struct.pack(
            "<12I",
            HELLO_RESP,
            0x30,
            SAHARA_V2,
            SAHARA_V2_MIN,
            0,
            COMMAND_MODE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)

        ready = read_exact(ep_in, 8)
        ready_cmd, ready_len = packet_header(ready)
        if ready_cmd == END_IMAGE_TRANSFER and ready_len == 16:
            read_end_image_transfer(ep_in, ready)
            return 0
        if ready_cmd != CMD_READY or ready_len != 8:
            print("Expected CMD_READY; stopped without sending a client command.")
            return 8

        print("CMD_READY received; sending exactly one client command (0x01).")
        ep_out.write(
            struct.pack("<III", CMD_EXEC, 12, SERIAL_NUM_READ),
            timeout=TIMEOUT_MS,
        )
        response = read_exact(ep_in, 16)
        cmd, length = packet_header(response)
        if cmd == END_IMAGE_TRANSFER and length == 16:
            _, _, image_id, status = struct.unpack("<4I", response)
            print(
                "SERIAL_NUM_READ rejected: "
                f"image_id={image_id} status=0x{status:x}; stopped without retry"
            )
            return 0
        if cmd != CMD_EXEC_RESP or length != 16:
            print("Unexpected EXEC response; stopped without requesting data.")
            return 9

        _, _, client_cmd, data_len = struct.unpack("<4I", response)
        if client_cmd != SERIAL_NUM_READ:
            print("EXEC response command ID mismatch; stopped without requesting data.")
            return 10
        if data_len != SERIAL_RESPONSE_BYTES:
            print(
                "SERIAL_NUM_READ advertised an unexpected response length "
                f"({data_len}); stopped without requesting data."
            )
            return 11

        ep_out.write(
            struct.pack("<III", CMD_EXEC_DATA, 12, SERIAL_NUM_READ),
            timeout=TIMEOUT_MS,
        )
        read_exact(ep_in, SERIAL_RESPONSE_BYTES)
        # Deliberately discard the bytes without decoding, printing, or saving them.
        print("SERIAL_NUM_READ succeeded; response_len=4; serial=redacted.")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara query ended with: {exc}; no retry sent.", file=sys.stderr)
        return 12
    except RuntimeError as exc:
        print(f"Sahara query stopped: {exc}; no retry sent.", file=sys.stderr)
        return 13
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
