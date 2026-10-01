#!/usr/bin/env python3
"""Read the complete USB configuration descriptor from Qualcomm EDL once.

The descriptor header already reported wTotalLength=32. This valid standard
GET_DESCRIPTOR request asks for exactly those 32 bytes so the EDL interface
and endpoint layout can be recorded. It sends no OUT data and no Sahara
command, performs no reset, and does not retry.
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
CONFIG_TOTAL_LENGTH = 32
TIMEOUT_MS = 1000


def describe_descriptors(payload: bytes) -> None:
    if len(payload) < 9 or payload[1] != USB_DT_CONFIG:
        print("response_shape=short_or_not_a_configuration_descriptor")
        return

    total_length = int.from_bytes(payload[2:4], "little")
    print(
        "configuration="
        f"bLength={payload[0]} wTotalLength={total_length} "
        f"bNumInterfaces={payload[4]} bConfigurationValue={payload[5]} "
        f"bmAttributes=0x{payload[7]:02x} bMaxPower={payload[8]}"
    )

    offset = 0
    while offset + 2 <= len(payload):
        length = payload[offset]
        descriptor_type = payload[offset + 1]
        if length < 2 or offset + length > len(payload):
            print(f"descriptor_parse_stopped=invalid_length_at_{offset}")
            return

        d = payload[offset : offset + length]
        if descriptor_type == 0x04 and length >= 9:
            print(
                "interface="
                f"number={d[2]} alternate={d[3]} endpoints={d[4]} "
                f"class=0x{d[5]:02x} subclass=0x{d[6]:02x} "
                f"protocol=0x{d[7]:02x}"
            )
        elif descriptor_type == 0x05 and length >= 7:
            endpoint_address = d[2]
            attributes = d[3]
            max_packet = int.from_bytes(d[4:6], "little")
            direction = "IN" if endpoint_address & 0x80 else "OUT"
            transfer_type = ("control", "isochronous", "bulk", "interrupt")[
                attributes & 0x03
            ]
            print(
                "endpoint="
                f"address=0x{endpoint_address:02x} direction={direction} "
                f"type={transfer_type} max_packet={max_packet} "
                f"interval={d[6]}"
            )

        offset += length


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="send the single 32-byte configuration-descriptor request",
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
        f"wIndex=0 wLength={CONFIG_TOTAL_LENGTH}"
    )

    try:
        data = dev.ctrl_transfer(
            REQUEST_TYPE_DEVICE_TO_HOST_STANDARD_DEVICE,
            USB_REQ_GET_DESCRIPTOR,
            w_value,
            0,
            CONFIG_TOTAL_LENGTH,
            timeout=TIMEOUT_MS,
        )
    except usb.core.USBError as exc:
        print(f"control_transfer_error={type(exc).__name__}: {exc}")
        return 0
    finally:
        usb.util.dispose_resources(dev)

    payload = bytes(data)
    print(f"response_len={len(payload)} hex={payload.hex()}")
    describe_descriptors(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
