#!/usr/bin/env python3
"""Read the USB BOS descriptor once from Qualcomm EDL over EP0.

This sends one standard device-to-host GET_DESCRIPTOR(BOS) request. It does
not send vendor requests, configure an interface, issue Sahara commands, reset
the target, retry, or save the returned bytes.
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
USB_DT_BOS = 0x0F
USB_DT_DEVICE_CAPABILITY = 0x10
BOS_INDEX = 0
REQUEST_LENGTH = 255
TIMEOUT_MS = 1000

# UUID bytes as serialized in the Microsoft OS 2.0 platform capability.
MS_OS_20_PLATFORM_UUID = bytes.fromhex(
    "df60ddd88945c74c9cd2659d9e648a9f"
)

CAPABILITY_NAMES = {
    0x02: "USB_2_0_EXTENSION",
    0x03: "SUPERSPEED_USB",
    0x04: "CONTAINER_ID",
    0x05: "PLATFORM",
    0x06: "POWER_DELIVERY",
    0x0A: "WIRELESS_USB",
    0x0B: "USB4",
}


def describe_bos(data: bytes) -> None:
    if len(data) < 5 or data[1] != USB_DT_BOS:
        print("response_shape=short_or_not_a_BOS_descriptor")
        return

    header_length = data[0]
    total_length = int.from_bytes(data[2:4], "little")
    capability_count = data[4]
    print(
        f"BOS=bLength={header_length} wTotalLength={total_length} "
        f"bNumDeviceCaps={capability_count}"
    )
    if header_length < 5 or header_length > len(data):
        print("result=invalid_BOS_header_length")
        return
    if total_length > len(data):
        print(f"result=truncated_BOS_descriptor missing={total_length - len(data)}")
    elif total_length < len(data):
        print(f"bytes_beyond_BOS={len(data) - total_length}")

    offset = header_length
    parsed = 0
    while offset + 3 <= min(total_length, len(data)) and parsed < capability_count:
        descriptor_length = data[offset]
        descriptor_type = data[offset + 1]
        descriptor_end = offset + descriptor_length
        if descriptor_length < 3 or descriptor_end > min(total_length, len(data)):
            print(f"capability[{parsed}]=malformed_descriptor_at_offset_0x{offset:x}")
            return
        descriptor = data[offset : offset + descriptor_length]
        if descriptor_type != USB_DT_DEVICE_CAPABILITY:
            print(
                f"capability[{parsed}]=unexpected_descriptor_type_"
                f"0x{descriptor_type:02x} length={descriptor_length}"
            )
            offset += descriptor_length
            parsed += 1
            continue

        capability_type = descriptor[2]
        name = CAPABILITY_NAMES.get(capability_type, "UNKNOWN")
        print(
            f"capability[{parsed}]=type=0x{capability_type:02x} "
            f"name={name} length={descriptor_length}"
        )
        if capability_type == 0x05 and descriptor_length >= 20:
            platform_uuid = descriptor[4:20]
            print(f"platform_uuid={platform_uuid.hex()}")
            if platform_uuid == MS_OS_20_PLATFORM_UUID and descriptor_length >= 28:
                windows_version = int.from_bytes(descriptor[20:24], "little")
                descriptor_set_length = int.from_bytes(descriptor[24:26], "little")
                vendor_code = descriptor[26]
                alt_enum_code = descriptor[27]
                print(
                    "ms_os_20_platform_capability="
                    f"windows_version=0x{windows_version:08x} "
                    f"descriptor_set_length={descriptor_set_length} "
                    f"vendor_code=0x{vendor_code:02x} "
                    f"alt_enum_code=0x{alt_enum_code:02x}"
                )
        offset += descriptor_length
        parsed += 1

    if parsed != capability_count:
        print(f"capabilities_parsed={parsed}/{capability_count}")
    elif capability_count == 0:
        print("capabilities_parsed=0")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-send",
        action="store_true",
        help="send the single 255-byte BOS descriptor request",
    )
    args = parser.parse_args()
    if not args.confirm_send:
        parser.error("refusing USB I/O without --confirm-send")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("Qualcomm 05c6:9008 is not visible to PyUSB", file=sys.stderr)
        return 2

    w_value = USB_DT_BOS << 8 | BOS_INDEX
    print(
        f"device={dev.idVendor:04x}:{dev.idProduct:04x} "
        f"bcdUSB=0x{dev.bcdUSB:04x} bDeviceClass=0x{dev.bDeviceClass:02x}"
    )
    print(
        "sending exactly one standard EP0 IN setup: "
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
        print("stopped_without_retry_or_follow_up_request")
        return 0
    finally:
        usb.util.dispose_resources(dev)

    print(f"response_len={len(response)}")
    print(f"response_sha256={hashlib.sha256(response).hexdigest()}")
    describe_bos(response)
    print("stopped_after_one_standard_read_only_request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
