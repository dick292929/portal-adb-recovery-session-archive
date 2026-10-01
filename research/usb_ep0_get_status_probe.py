#!/usr/bin/env python3
"""Send one bounded USB 2.0 device GET_STATUS IN request to Qualcomm EDL.

This checks how the EDL USB device handles a standard device request with an
overlong host wLength. It sends no OUT payload, issues no reset, and does not
send Sahara traffic. A stall is recorded as a result, not retried.
"""

from __future__ import annotations

import argparse
import sys

import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE = 0x80
USB_REQ_GET_STATUS = 0x00
READ_LENGTH = 64
TIMEOUT_MS = 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="send the single 64-byte device-to-host GET_STATUS request",
    )
    args = parser.parse_args()

    if not args.confirm_send:
        parser.error("refusing USB I/O without --confirm-send")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("Qualcomm 05c6:9008 is not visible to PyUSB", file=sys.stderr)
        return 2

    print(
        f"device={dev.idVendor:04x}:{dev.idProduct:04x} "
        f"bcdUSB=0x{dev.bcdUSB:04x} bDeviceClass=0x{dev.bDeviceClass:02x}"
    )
    print(
        "sending exactly one EP0 IN setup: "
        "bmRequestType=0x80 bRequest=0x00 wValue=0 wIndex=0 wLength=64"
    )

    try:
        data = dev.ctrl_transfer(
            REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE,
            USB_REQ_GET_STATUS,
            0,
            0,
            READ_LENGTH,
            timeout=TIMEOUT_MS,
        )
    except usb.core.USBError as exc:
        print(f"control_transfer_error={type(exc).__name__}: {exc}")
        return 0
    finally:
        usb.util.dispose_resources(dev)

    payload = bytes(data)
    print(f"response_len={len(payload)} hex={payload.hex()}")
    print("ascii=" + "".join(chr(b) if 32 <= b < 127 else "." for b in payload))
    if len(payload) > 2:
        print("response_shape=longer_than_the_two-byte_USB_device_status")
    elif len(payload) == 2:
        print("response_shape=two_byte_device_status")
    else:
        print("response_shape=short_or_empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
