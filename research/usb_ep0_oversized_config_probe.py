#!/usr/bin/env python3
"""One read-only oversized USB configuration-descriptor request to Qualcomm EDL.

The Portal previously returned a 32-byte configuration descriptor whose
wTotalLength is 32. This probe asks for 512 bytes in one standard EP0 IN
GET_DESCRIPTOR request. A compliant target should return only the 32-byte
descriptor. If it returns more, the extra bytes may indicate an EP0 over-read;
the script reports only the length and a short sample, and never saves data.

Exactly one request is sent. No Sahara command, OUT transfer, reset, or retry is
performed.
"""

from __future__ import annotations

import argparse
import hashlib
import sys

import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE = 0x80
USB_REQ_GET_DESCRIPTOR = 0x06
USB_DT_CONFIG = 0x02
CONFIG_INDEX = 0
REQUEST_LENGTH = 512
TIMEOUT_MS = 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="send the single 512-byte EP0 IN descriptor request",
    )
    args = parser.parse_args()

    if not args.confirm_send:
        parser.error("refusing USB I/O without --confirm-send")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("Qualcomm 05c6:9008 is not visible to PyUSB", file=sys.stderr)
        return 2

    w_value = (USB_DT_CONFIG << 8) | CONFIG_INDEX
    print(
        f"device={dev.idVendor:04x}:{dev.idProduct:04x} "
        f"bcdUSB=0x{dev.bcdUSB:04x} bDeviceClass=0x{dev.bDeviceClass:02x}"
    )
    print(
        "sending exactly one EP0 IN setup: "
        f"bmRequestType=0x80 bRequest=0x06 wValue=0x{w_value:04x} "
        f"wIndex=0 wLength={REQUEST_LENGTH}"
    )

    try:
        response = bytes(
            dev.ctrl_transfer(
                REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE,
                USB_REQ_GET_DESCRIPTOR,
                w_value,
                0,
                REQUEST_LENGTH,
                timeout=TIMEOUT_MS,
            )
        )
    except usb.core.USBError as exc:
        print(f"control_transfer_error={type(exc).__name__}: {exc}")
        return 0
    finally:
        usb.util.dispose_resources(dev)

    print(f"response_len={len(response)}")
    print(f"response_sha256={hashlib.sha256(response).hexdigest()}")
    if len(response) >= 4 and response[1] == USB_DT_CONFIG:
        total_length = int.from_bytes(response[2:4], "little")
        print(f"descriptor_wTotalLength={total_length}")
        extra = response[total_length:] if total_length <= len(response) else b""
        print(f"bytes_beyond_descriptor={len(extra)}")
        if extra:
            print(f"extra_sample_hex={extra[:32].hex()}")
            print("result=oversized_descriptor_response")
        else:
            print("result=no_bytes_beyond_advertised_descriptor")
    else:
        print("response_shape=short_or_not_a_configuration_descriptor")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
