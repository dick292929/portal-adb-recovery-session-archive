#!/usr/bin/env python3
"""Retired guard for the completed 26-cycle qtestsign differential.

The Portal returned END_IMAGE_TX 0x28 before any image-body bytes. The
QPSS22 presentation does not identify the 26/27-reset test target or match it
to APQ8098. Repeating this image/reset probe cannot test the MSM8998 exploit
path. This file performs no USB discovery or I/O.
"""


def main() -> int:
    print(
        "STOPPED: this qtestsign run ended at END_IMAGE_TX 0x28 before image-body "
        "transfer, and its 26-reset parameter is not matched to the Portal. "
        "No USB device was opened and no packet was sent. See "
        "research/SESSION_RECORD_2026-09-28.md for the current source audit."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
