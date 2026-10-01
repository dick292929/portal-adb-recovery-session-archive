#!/usr/bin/env python3
"""Retired guard for the already-completed Portal 0x13 reset/hash check.

The raw one-byte RESET_STATE_MACHINE input was already exercised on this
Portal. The recorded run received HELLO through reset 121 and timed out waiting
for reset 122, without an OEM PK-hash change or access signal. Replaying it
would repeat the same crash-boundary test, so this file deliberately performs
no USB discovery or I/O.
"""

import sys


def main() -> int:
    print(
        "STOPPED: this Portal's one-byte Sahara 0x13 reset/hash check was "
        "already run (HELLO through reset 121; timeout at reset 122; hash "
        "unchanged). No USB device was opened and no packet was sent."
    )
    print(
        "See research/SESSION_RECORD_2026-09-27.md and "
        "research/SESSION_RECORD_2026-09-28.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
