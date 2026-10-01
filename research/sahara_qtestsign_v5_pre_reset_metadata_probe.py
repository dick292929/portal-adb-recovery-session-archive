#!/usr/bin/env python3
"""Retired no-I/O guard for the unused qtestsign metadata control.

The control would only compare a non-target-matched inert image's metadata
rejection with and without reset words. It cannot exercise the documented
MSM8998 RSA-modulus landing path. No USB discovery or I/O is performed.
"""


def main() -> int:
    print(
        "STOPPED: the qtestsign metadata control was retired because it cannot "
        "test the APQ8098/MSM8998 CVE path. No USB device was opened and no "
        "packet was sent. See research/SESSION_RECORD_2026-09-28.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
