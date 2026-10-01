#!/usr/bin/env python3
"""Read one USB configuration-descriptor header from Qualcomm EDL.

This is a standard, device-to-host descriptor request. It reads only the
9-byte configuration header to identify the advertised interface count,
attributes, and complete descriptor length. It sends no OUT data, reset, or
Sahara command and does not retry.
"""

from __future__ import annotations

import argparse
import sys

import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE = 0x80
USB_REQ_GET_DESCRIPTOR = 0x06
USB_DT_CONFIG = 0x02
CONFIG_INDEX = 0
HEADER_LENGTH = 9
TIMEOUT_MS = 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="send the single 9-byte configuration-descriptor request",
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
        f"wIndex=0 wLength={HEADER_LENGTH}"
    )

    try:
        data = dev.ctrl_transfer(
            REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE,
            USB_REQ_GET_DESCRIPTOR,
            w_value,
            0,
            HEADER_LENGTH,
            timeout=TIMEOUT_MS,
        )
    except usb.core.USBError as exc:
        print(f"control_transfer_error={type(exc).__name__}: {exc}")
        return 0
    finally:
        usb.util.dispose_resources(dev)

    payload = bytes(data)
    print(f"response_len={len(payload)} hex={payload.hex()}")
    if len(payload) >= HEADER_LENGTH and payload[1] == USB_DT_CONFIG:
        total_length = int.from_bytes(payload[2:4], "little")
        print(
            "descriptor="
            f"bLength={payload[0]} bDescriptorType=0x{payload[1]:02x} "
            f"wTotalLength={total_length} bNumInterfaces={payload[4]} "
            f"bConfigurationValue={payload[5]} "
            f"bmAttributes=0x{payload[7]:02x} "
            f"bMaxPower={payload[8]}"
        )
        print(f"remote_wakeup_capable={bool(payload[7] & 0x20)}")
    else:
        print("response_shape=short_or_not_a_configuration_header")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
