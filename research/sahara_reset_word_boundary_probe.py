#!/usr/bin/env python3
"""Bounded 26/27-cycle OEM-PK-hash check using the QPSS22 four-byte word.

Requires full power-off and fresh EDL entry. Reads the recorded OEM PK hash,
sends the exact `13 9a 9a 9a` reset word up to 27 times, and re-reads the hash
after each HELLO. Stops on the first unexpected response, timeout, or hash
change. This measures only the public-key-hash field; it does not test image
signature verification or execute an image.
"""

import argparse
import struct
import sys

import usb.backend.libusb1
import usb.core
import usb.util

from sahara_reset_word_pkhash_probe import (
    END_IMAGE_TRANSFER,
    EXPECTED_PK_HASH,
    HELLO,
    PID,
    RESET_WORD,
    TIMEOUT_MS,
    VID,
    StopProbe,
    enter_command_mode,
    read_pk_hash,
    send_exact,
)

MAX_CYCLES = 27


def read_reset_reply(ep_in):
    # The known HELLO response is 48 bytes. Read a full bounded packet so the
    # USB backend does not overflow an 8-byte header buffer.
    response = bytes(ep_in.read(0x30, timeout=TIMEOUT_MS))
    if len(response) < 8:
        raise StopProbe(f"short reset response: received {len(response)} bytes")

    command, length = struct.unpack_from("<II", response)
    if command == END_IMAGE_TRANSFER and length == 16:
        if len(response) != 16:
            raise StopProbe(
                f"END_IMAGE_TRANSFER declared 16 bytes, received {len(response)}"
            )
        _, _, image_id, status = struct.unpack("<4I", response)
        raise StopProbe(
            f"reset word rejected at this cycle: image_id={image_id} "
            f"status=0x{status:x}"
        )
    if command != HELLO or length != 0x30 or len(response) != 0x30:
        raise StopProbe(
            f"unexpected reset response cmd=0x{command:x} length=0x{length:x} "
            f"received={len(response)}"
        )
    return response


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
            "checking baseline OEM PK hash"
        )
        baseline, response_len = read_pk_hash(ep_in, ep_out)
        print(
            f"baseline_hash_read=ok response_len={response_len} "
            f"normalized_len={len(baseline)}"
        )
        if baseline != EXPECTED_PK_HASH:
            print(
                "baseline does not match the recorded Portal identity; "
                "stopped before any reset word"
            )
            return 5

        print(
            f"Sending exact QPSS22 reset word at most {MAX_CYCLES} times; "
            "hash values remain redacted"
        )
        for cycle in range(1, MAX_CYCLES + 1):
            send_exact(ep_out, RESET_WORD, f"reset word at cycle {cycle}")
            response = read_reset_reply(ep_in)
            enter_command_mode(ep_in, ep_out, initial_hello=response)
            current, response_len = read_pk_hash(ep_in, ep_out)
            changed = current != baseline
            print(
                f"cycle={cycle} response_len={response_len} "
                f"normalized_len={len(current)} changed_from_baseline="
                f"{str(changed).lower()}"
            )
            if changed:
                print("Hash changed; stopped immediately without another reset.")
                return 0

        print(
            "Stopped at cycle 27; OEM PK hash remained unchanged. "
            "No image, memory, or storage command sent."
        )
        return 0
    except usb.core.USBError as exc:
        print(f"USB/Sahara error={exc}; stopped without retry", file=sys.stderr)
        return 6
    except StopProbe as exc:
        print(f"Probe stopped: {exc}; no further reset word sent", file=sys.stderr)
        return 7
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    raise SystemExit(main())
