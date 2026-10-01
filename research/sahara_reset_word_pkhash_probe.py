#!/usr/bin/env python3
"""Compare the recorded OEM PK hash around one QPSS22 reset-word candidate.

Requires a full power-off and fresh EDL entry. Reads the OEM public-key hash,
sends exactly one 4-byte `13 9a 9a 9a` candidate, then reads the hash once more
if Sahara returns to command mode. It prints no hash bytes and sends no image,
memory, or storage command.
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
OEM_PK_HASH_READ = 0x03

EXPECTED_PK_HASH = bytes.fromhex(
    "7291ef5c5d99dc05ee00237a1d71b1f572696870b839bb715fba9e89988b4a3f"
)
RESET_WORD = bytes.fromhex("13 9a 9a 9a")
PK_HASH_LENGTH = 32
MAX_PK_HASH_RESPONSE_LENGTH = 256


class StopProbe(Exception):
    pass


def read_exact(endpoint, length):
    result = bytearray()
    while len(result) < length:
        chunk = endpoint.read(length - len(result), timeout=TIMEOUT_MS)
        if not chunk:
            raise StopProbe(f"short USB read: got {len(result)} of {length} bytes")
        result.extend(chunk)
    return bytes(result)


def send_exact(endpoint, data, description):
    written = endpoint.write(data, timeout=TIMEOUT_MS)
    if written != len(data):
        raise StopProbe(f"short {description} write: {written}/{len(data)}; stopping")


def hello_response(version, version_min):
    return struct.pack(
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


def enter_command_mode(ep_in, ep_out, initial_hello=None):
    hello = initial_hello if initial_hello is not None else read_exact(ep_in, 0x30)
    fields = struct.unpack("<12I", hello)
    if fields[0] != HELLO or fields[1] != 0x30:
        raise StopProbe("expected a 48-byte HELLO; stopped")
    version, version_min, max_packet, mode = fields[2:6]
    if version != 2 or version_min != 1 or max_packet < 0x30 or mode != 0:
        raise StopProbe(
            f"unexpected HELLO parameters v={version} min={version_min} "
            f"max_packet={max_packet} mode={mode}; stopped"
        )

    send_exact(ep_out, hello_response(version, version_min), "HELLO_RESP")
    ready = read_exact(ep_in, 8)
    ready_cmd, ready_len = struct.unpack("<II", ready)
    if ready_cmd == END_IMAGE_TRANSFER and ready_len == 16:
        tail = read_exact(ep_in, 8)
        _, _, image_id, status = struct.unpack("<4I", ready + tail)
        raise StopProbe(
            f"command-mode entry rejected: image_id={image_id} status=0x{status:x}"
        )
    if (ready_cmd, ready_len) != (CMD_READY, 8):
        raise StopProbe("expected CMD_READY after HELLO_RESP; stopped")
    return version, version_min, max_packet, mode


def read_pk_hash(ep_in, ep_out):
    send_exact(
        ep_out,
        struct.pack("<III", CMD_EXEC, 12, OEM_PK_HASH_READ),
        "OEM_PK_HASH_READ EXEC",
    )
    response = read_exact(ep_in, 16)
    cmd, length, client_cmd, data_len = struct.unpack("<4I", response)
    if cmd == END_IMAGE_TRANSFER and length == 16:
        raise StopProbe(
            f"OEM_PK_HASH_READ rejected: image_id={client_cmd} status=0x{data_len:x}"
        )
    if (cmd, length, client_cmd) != (CMD_EXEC_RESP, 16, OEM_PK_HASH_READ):
        raise StopProbe(
            "unexpected OEM_PK_HASH_READ EXEC response "
            f"cmd=0x{cmd:x} length=0x{length:x} client_cmd=0x{client_cmd:x} "
            f"data_len=0x{data_len:x}; "
            "no data request sent"
        )
    if not PK_HASH_LENGTH <= data_len <= MAX_PK_HASH_RESPONSE_LENGTH:
        raise StopProbe(
            f"OEM_PK_HASH_READ advertised {data_len} bytes outside the "
            f"bounded {PK_HASH_LENGTH}..{MAX_PK_HASH_RESPONSE_LENGTH} range; "
            "no data request sent"
        )

    send_exact(
        ep_out,
        struct.pack("<III", CMD_EXEC_DATA, 12, OEM_PK_HASH_READ),
        "OEM_PK_HASH_READ EXEC_DATA",
    )
    raw = read_exact(ep_in, data_len)
    if len(raw) == PK_HASH_LENGTH:
        return raw, data_len

    # Match the extraction already used by the earlier Portal reset/hash
    # probe: the OEM hash response may be wrapped/repeated in a larger block.
    marker = raw[:4]
    duplicate = raw[4:].find(marker)
    if duplicate < 0:
        raise StopProbe(
            f"OEM_PK_HASH_READ returned {data_len} bytes with an "
            "unrecognized bounded response shape"
        )
    normalized = raw[: 4 + duplicate]
    if len(normalized) != PK_HASH_LENGTH:
        raise StopProbe(
            f"OEM_PK_HASH_READ response normalized to {len(normalized)} bytes, "
            f"expected {PK_HASH_LENGTH}"
        )
    return normalized, data_len


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-fresh-edl-entry",
        action="store_true",
        help="required after full power-off followed by a fresh EDL entry",
    )
    args = parser.parse_args()
    if not args.confirm_fresh_edl_entry:
        parser.error("requires --confirm-fresh-edl-entry after a fresh EDL entry")

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

        version, version_min, max_packet, mode = enter_command_mode(ep_in, ep_out)
        print(
            f"HELLO v={version} min={version_min} max_packet={max_packet} mode={mode}; "
            "reading baseline OEM PK hash"
        )
        baseline, baseline_response_len = read_pk_hash(ep_in, ep_out)
        print(
            f"baseline_hash_read=ok response_len={baseline_response_len} "
            f"normalized_len={len(baseline)}"
        )
        if baseline != EXPECTED_PK_HASH:
            print(
                "baseline does not match the recorded Portal identity; "
                "stopped before sending the reset-word candidate"
            )
            return 5

        print("Sending exactly one reset-word candidate: 13 9a 9a 9a")
        send_exact(ep_out, RESET_WORD, "reset-word candidate")
        # The Portal's observed reset response is a 48-byte HELLO. Read into
        # a full bounded packet buffer; an 8-byte bulk read can overflow when
        # the device returns that complete 48-byte USB packet.
        response = bytes(ep_in.read(0x30, timeout=TIMEOUT_MS))
        if len(response) < 8:
            raise StopProbe(
                f"short post-candidate packet: received {len(response)} bytes"
            )
        response_cmd, response_len = struct.unpack_from("<II", response)
        if response_cmd == END_IMAGE_TRANSFER and response_len == 16:
            if len(response) != 16:
                raise StopProbe(
                    f"END_IMAGE_TRANSFER declared 16 bytes, received {len(response)}"
                )
            _, _, image_id, status = struct.unpack("<4I", response)
            print(
                f"candidate rejected: image_id={image_id} status=0x{status:x}; stopped"
            )
            return 0
        if response_cmd != HELLO or response_len != 0x30 or len(response) != 0x30:
            print(
                f"unexpected post-candidate response cmd=0x{response_cmd:x} "
                f"length=0x{response_len:x} received={len(response)}; "
                "stopped without another command"
            )
            return 6

        enter_command_mode(ep_in, ep_out, initial_hello=response)
        after, after_response_len = read_pk_hash(ep_in, ep_out)
        changed = after != baseline
        print(
            f"post_hash_read=ok response_len={after_response_len} "
            f"normalized_len={len(after)}"
        )
        print(f"oem_pk_hash_changed={str(changed).lower()}; hash=redacted")
        print("Stopped; no retry, image body, memory request, or storage command sent.")
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara error={exc}; stopped without retry", file=sys.stderr)
        return 7
    except StopProbe as exc:
        print(f"Probe stopped: {exc}", file=sys.stderr)
        return 8
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
