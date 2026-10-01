#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Daniel Grobert <danalexgro@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#

import usb.core
import usb.util
import usb.backend.libusb1
import libusb
import logging
import sys
import os
import time
from struct import pack
import katana

logger  = logging.getLogger(__name__)

EDL_VID = 0x05C6
EDL_PID = 0x9008
 
USB_TIMEOUT_MS = 1500
USB_READ_SIZE  = 0x1000

# from QSaharaServer
SAHARA_HELLO_ID = 0x01
SAHARA_HELLO_RESP_ID = 0x02
SAHARA_READ_DATA_ID = 0x03
SAHARA_END_IMAGE_TX_ID = 0x04
SAHARA_DONE_ID = 0x05
SAHARA_DONE_RESP_ID = 0x06
SAHARA_RESET_ID = 0x07
SAHARA_RESET_RESP_ID = 0x08
SAHARA_MEMORY_DEBUG_ID = 0x09
SAHARA_MEMORY_READ_ID = 0x0A
SAHARA_CMD_READY_ID = 0x0B
SAHARA_CMD_SWITCH_MODE_ID = 0x0C
SAHARA_CMD_EXEC_ID = 0x0D
SAHARA_CMD_EXEC_RESP_ID = 0x0E
SAHARA_CMD_EXEC_DATA_ID = 0x0F
SAHARA_64_BITS_MEMORY_DEBUG_ID = 0x10
SAHARA_64_BITS_MEMORY_READ_ID = 0x11
SAHARA_64_BITS_READ_DATA_ID = 0x12
SAHARA_RESET_STATE_MACHINE_ID = 0x13

SAHARA_MODE_IMAGE_TX_PENDING = 0x0
SAHARA_MODE_IMAGE_TX_COMPLETE = 0x1
SAHARA_MODE_MEMORY_DEBUG = 0x2
SAHARA_MODE_COMMAND = 0x3

class EDLDevice:
    verbose = False
    vid = 0x05C6
    pid = 0x9008

    def __init__(self):
        self.dev    = None
        self.ep_in  = None
        self.ep_out = None
 
    def connect(self) -> bool:
        logger.info("Waiting for Qualcomm device in Sahara state")
 
        backend = usb.backend.libusb1.get_backend()
        if backend is None:
            logger.error(
                "libusb not found."
                "If you're on Windows, please install Zadig drivers"
            )
            return False
        
        while True:
            self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=backend)
            if self.dev is not None:
                logger.info("Found device!")
                break
            time.sleep(1)

 
        # Detach kernel driver on Linux
        if sys.platform != "win32":
            try:
                if self.dev.is_kernel_driver_active(0):
                    logger.debug("Detaching kernel driver")
                    self.dev.detach_kernel_driver(0)
            except usb.core.USBError as e:
                logger.warning("Could not detach kernel driver: %s", e)
 
        self.dev.set_configuration()
 
        cfg  = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
 
        self.ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
        )
        self.ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
        )
 
        logger.info("Connected to device")
        return True

    # There's a chance where the exploit may fail when the device is crashed
    # into PBL Sahara (unsigned XBL). This state is not pwnable and libusb will throw a timeout error.
    # Modifying ABL or HYP is safe, because SBL1 will reboot (i think) normally into Sahara. 
    def crash_notice(self):
        logger.critical("")
        logger.critical("Exploit failed!")
        logger.critical("Possible causes may be:")
        logger.critical("    - Missing XBL")
        logger.critical("    - Missing XBL_SEC")
        logger.critical("    - Booting a testsigned or unsigned XBL")
        logger.critical("    - PBL being crashed into Sahara (most common cause)")
        logger.critical("The state where PBL is crashed into Sahara is unfortunately not exploitable.")
        logger.critical("It is recommended not to modify XBL to avoid a crash")
        logger.critical("Please boot into a clean Sahara state using the testpoints on the motherboard")
        logger.critical("or using an EDL cable.")
        exit()

    def write(self, data: bytes) -> int:
        try:
            if self.verbose:
                logger.debug(f"\nTX (0x{len(data):x}): {data.hex()}\n")

            return self.ep_out.write(data, timeout=USB_TIMEOUT_MS)

        except usb.core.USBTimeoutError:
            self.crash_notice()
 
    def read(self, size: int = USB_READ_SIZE) -> bytes:
        try:
            data = bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        except usb.core.USBTimeoutError:
            self.crash_notice()
        if self.verbose == True:
            logger.debug(f"\nRX (0x{len(data):x}): {data.hex()}\n")
        return data

    def payload_read(self, size: int = USB_READ_SIZE) -> bytes:
        try:
            data = bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        except usb.core.USBTimeoutError:
            self.crash_notice()

        if self.verbose:
            logger.debug(f"\nRX (0x{len(data):x}): {data.hex()}\n")

        ascii_region = data[0x0:0x400]
        ascii_text = ''.join(
            chr(b) if 32 <= b <= 126 else ''
            for b in ascii_region
        )

        logger.debug(f"Payload: {ascii_text}")

        return data

    def close(self):
        if self.dev:
            usb.util.dispose_resources(self.dev)
            self.dev = None
            logger.info("Device released.")

def send_hello_resp(edl, mode, ver_min, switch_mode, version):
    length = 0x30
    resp_packet = pack("<IIIIIIIIIIII", SAHARA_HELLO_RESP_ID, length, version, ver_min, 0x0, switch_mode, 0, 0, 0, 0, 0, 0)
    edl.write(resp_packet)
    