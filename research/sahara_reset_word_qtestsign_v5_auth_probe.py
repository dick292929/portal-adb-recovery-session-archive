#!/usr/bin/env python3
"""Retired guard for the completed 27-cycle qtestsign attempt.

The Portal's prior run stopped with END_IMAGE_TX status 0x28 before any
image-body bytes. This file intentionally performs no USB discovery or I/O.
The fixed 26-cycle differential also ended at the same pre-body status, and
QPSS22 does not identify its test target as APQ8098/MSM8998. Both branches are
closed; the actual MSM8998 exploit flow requires an accepted image before its
one-byte reset recursion and a target-specific landing sequence.
"""


def main() -> int:
    print(
        "STOPPED: the Portal's 27-cycle qtestsign attempt already ended at "
        "END_IMAGE_TX 0x28 before image-body transfer. The 26-cycle run also "
        "stopped at that boundary, and QPSS22 does not match its target to "
        "APQ8098/MSM8998. Do not repeat either qtestsign/reset probe. No USB "
        "device was opened and no packet was sent."
    )
    print("See research/SESSION_RECORD_2026-09-28.md for the source audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
