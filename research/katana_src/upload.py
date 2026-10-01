#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Daniel Grobert <danalexgro@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#

import struct
import coloredlogs
import logging
from struct import pack
from modules.sahara import *
from soc_data import SOC_DATA

logger  = logging.getLogger(__name__)

def upload_loader(edl, path: str):
    with open(path, "rb") as f:
        programmer = f.read()

    while True:
        data = edl.read(size=0x30)

        cmd = struct.unpack_from("<I", data, 0)[0]

        if cmd == SAHARA_READ_DATA_ID:
            _, _, image_id, data_offset, data_len = \
                struct.unpack_from("<IIIII", data, 0)

        elif cmd == SAHARA_64_BITS_READ_DATA_ID:
            image_id = struct.unpack_from("<I", data, 8)[0]
            data_offset = struct.unpack_from("<Q", data, 16)[0]
            data_len = struct.unpack_from("<Q", data, 24)[0]

        elif cmd == SAHARA_END_IMAGE_TX_ID:
            _, _, image_id, status = \
                struct.unpack_from("<IIII", data, 0)

            if status == 0:
                logger.info("Transfer complete, telling PBL it's done")

                edl.write(pack("<II", SAHARA_DONE_ID, 0x8))
                rsp = edl.read(size=0x30)
                done_cmd = struct.unpack_from("<I", rsp, 0)[0]
                if done_cmd == SAHARA_DONE_RESP_ID:
                    logger.info("Loader uploaded successfully")
                    return True

                logger.error(f"Expected SAHARA_DONE_RESP_ID, got 0x{done_cmd:x}")
                return False

            logger.error(f"Transfer failed, status=0x{status:x}")
            return False

        else:
            logger.error(f"Unexpected command received during upload: 0x{cmd:x}")
            return False
        
        temp_prog = programmer

        end = data_offset + data_len

        if end > len(temp_prog):
            temp_prog += b"\xff" * (end - len(temp_prog))

        chunk = temp_prog[data_offset:end]

        edl.write(chunk)

def upload_exploit_payload(edl, path: str, soc):
    with open(path, "rb") as f:
        payload = f.read()

    # We split bulk transfers to 200 byte chunks, 
    # which seems to be the safest option..
    CHUNK_SIZE = 0x200

    while True:
        pkt_req = edl.read(size=0x20)
        cmd, = struct.unpack_from("<I", pkt_req, 0)
        offset, = struct.unpack_from("<Q", pkt_req, 0x10)
        size, = struct.unpack_from("<Q", pkt_req, 0x18)

        # I'm not sure if PBL will copy shellcode past 0x2000
        if offset == 0x2000:
            logger.debug("Payload transferred")
            edl.write(b"")
            if cmd == 0x12:
                logger.debug("The BootROM is still requesting data, uploading nulls")
            else:
                exit()    
            for _ in range(SOC_DATA[soc]["send_null_cnt"]):
                edl.write(b"\x00" * 0x200)
            edl.write(b"")
            break        

        logger.warning(f"Sending payload segment, offset=0x{offset:x} size=0x{size:x}")

        raw = payload[offset:offset + size]
        data = raw.ljust(size, b'\x00')

        sent = 0
        while sent < len(data):
            chunk = data[sent:sent + CHUNK_SIZE]
            edl.write(chunk)
            sent += len(chunk)
