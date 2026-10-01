#!/usr/bin/env python3
"""Issue one Sahara EXEC switch-to-streaming-DLOAD request (client command 0x05)."""

import sahara_exec_dmss_dload_probe as probe


probe.CLIENT_COMMAND = 0x05
probe.MODE_NAME = "SWITCH_TO_STREAM_DLOAD"


if __name__ == "__main__":
    raise SystemExit(probe.main())
