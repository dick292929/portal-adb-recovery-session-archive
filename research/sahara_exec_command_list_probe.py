#!/usr/bin/env python3
"""Read Sahara's advertised EXEC client-command list from a fresh EDL entry."""

import argparse
import struct
import sys

import usb.backend.libusb1
import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
TIMEOUT_MS = 3000
MAX_RESPONSE_BYTES = 4096

HELLO = 0x01
HELLO_RESP = 0x02
CMD_READY = 0x0B
CMD_EXEC = 0x0D
CMD_EXEC_RESP = 0x0E
CMD_EXEC_DATA = 0x0F
END_IMAGE_TRANSFER = 0x04
GET_COMMAND_ID_LIST = 0x08
COMMAND_MODE = 0x03


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
        raise RuntimeError(f"short Sahara packet: {data.hex()}")
    return struct.unpack_from("<II", data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required: confirm the Portal was fully powered off and freshly entered EDL",
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
        fields = struct.unpack_from("<12I", hello)
        if fields[0] != HELLO or fields[1] != 0x30:
            print(f"Unexpected initial Sahara packet {hello.hex()}; stopping.")
            return 5

        version, version_min = fields[2], fields[3]
        print(
            f"HELLO version={version} min={version_min} mode={fields[5]}; "
            "entering command mode for one read-only EXEC query"
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
        ep_out.write(hello_resp, timeout=TIMEOUT_MS)
        ready = read_exact(ep_in, 8)
        ready_cmd, ready_len = packet_header(ready)
        if ready_cmd != CMD_READY or ready_len != 8:
            if ready_cmd == END_IMAGE_TRANSFER and ready_len == 16:
                response = ready + read_exact(ep_in, 8)
                _, _, image_id, status = struct.unpack("<4I", response)
                print(
                    f"Command-mode entry rejected: END_IMAGE_TRANSFER "
                    f"image_id={image_id} status=0x{status:x} raw={response.hex()}"
                )
            else:
                print(f"Expected CMD_READY; received {ready.hex()}")
            return 6

        ep_out.write(struct.pack("<III", CMD_EXEC, 12, GET_COMMAND_ID_LIST), timeout=TIMEOUT_MS)
        response = read_exact(ep_in, 16)
        cmd, length = packet_header(response)
        if cmd == END_IMAGE_TRANSFER:
            _, _, image_id, status = struct.unpack("<4I", response)
            print(
                f"GET_COMMAND_ID_LIST rejected: END_IMAGE_TRANSFER "
                f"image_id={image_id} status=0x{status:x} raw={response.hex()}"
            )
            return 0
        if cmd != CMD_EXEC_RESP or length != 16:
            print(f"Unexpected EXEC response {response.hex()}; stopping without follow-up.")
            return 7

        _, _, client_cmd, data_len = struct.unpack("<4I", response)
        print(f"EXECUTE_RESP client_cmd=0x{client_cmd:x} data_len={data_len}")
        if client_cmd != GET_COMMAND_ID_LIST:
            print("Response command ID mismatch; stopping without requesting data.")
            return 8
        if data_len > MAX_RESPONSE_BYTES:
            print(
                f"Advertised response exceeds {MAX_RESPONSE_BYTES} bytes; "
                "stopping without requesting its data."
            )
            return 9

        ep_out.write(
            struct.pack("<III", CMD_EXEC_DATA, 12, GET_COMMAND_ID_LIST),
            timeout=TIMEOUT_MS,
        )
        payload = read_exact(ep_in, data_len) if data_len else b""
        print(f"command_id_list_bytes={len(payload)} raw={payload.hex()}")
        if payload and len(payload) % 4 == 0:
            words = struct.unpack("<" + "I" * (len(payload) // 4), payload)
            print("command_id_list_u32=" + ",".join(f"0x{x:x}" for x in words))
        print("Stopped after this single read-only query; no reset, image, memory, or storage command sent.")
        return 0
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
