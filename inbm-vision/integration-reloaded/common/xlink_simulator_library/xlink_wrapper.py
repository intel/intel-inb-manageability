"""
    Allows API of xlink driver C library to be called in Python.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import threading
from ctypes import *
from time import sleep

logger = logging.getLogger(__name__)

XLinkDeviceTypes_t = c_int
XLinkError_t = c_int
channelId_t = c_int
linkId_t = c_uint8
dataAddr = c_char_p
xLinkCallback_t = CFUNCTYPE(None, channelId_t, dataAddr)
(VPU_DEVICE, PCIE_DEVICE, USB_DEVICE, IPC_DEVICE,
 ETH_DEVICE, NMB_OF_DEVICE_TYPES) = (0, 1, 2, 3, 4, 5)
(USB_VSC, USB_CDC, PCIE, IPC, NMB_OF_PROTOCOLS) = (0, 1, 2, 3, 4)
(X_LINK_SUCCESS, X_LINK_ALREADY_OPEN, X_LINK_COMMUNICATION_NOT_OPEN, X_LINK_COMMUNICATION_FAIL,
 X_LINK_COMMUNICATION_UNKNOWN_ERROR, X_LINK_DEVICE_NOT_FOUND, X_LINK_TIMEOUT, X_LINK_ERROR) = (
0, 1, 2, 3, 4, 5, 6, 7)
(DEFAULT_NOMINAL_MAX, POWER_SAVING_MEDIUM, POWER_SAVING_HIGH) = (0, 1, 2)
(RXB_TXB, RXN_TXN, RXB_TXN, RXN_TXB) = (0, 1, 2, 3)


class XLinkProf_t(Structure):
    """Struct of XLinkProf_t"""
    _fields_ = [(
        "totalReadTime", c_float), ("totalWriteTime", c_float), ("totalReadBytes", c_ulong),
        ("totalWriteBytes", c_ulong), ("totalBootCount", c_ulong), ("totalBootTime", c_float)]


class XLinkHandler_t(Structure):
    """Struct of XLinkHandler_t"""
    _fields_ = [("devicePath", c_char_p), ("devicePath2", c_char_p), ("linkId", linkId_t),
                ("deviceType", XLinkDeviceTypes_t)]


class XLinkGlobalHandler_t(Structure):
    """Struct of XLinkGlobalHandler_t"""
    _fields_ = [(
        "loglevel", c_int), ("profEnable", c_int), ("protocol", c_int),
        ("profilingData", XLinkProf_t),
        ("serverAddress", c_wchar_p)]


class XlinkWrapper(object):
    """Wrapper class to use xlink shared library"""

    def __init__(self, XlinkPClibraryPath, receive_callback, channel_id):
        self.myXLinkPClib = self._load_library(XlinkPClibraryPath)
        self.receive_callback_method = receive_callback
        self.XlinkHandler = XLinkHandler_t(
            devicePath="/tmp/xlink_mock".encode('utf-8', errors='strict'), deviceType=PCIE_DEVICE)
        self.channelId = channelId_t(channel_id)
        self.ghandler = XLinkGlobalHandler_t(protocol=PCIE)
        self.DATA_FRAGMENT_SIZE = 1024
        self.operationType = RXN_TXN
        self.running = True
        self._init_channel()
        self.listen_thread = threading.Thread(target=self._listen_to_channel)

    def _load_library(self, library_path):
        return CDLL(library_path)

    def _init_channel(self):
        """Initialize Xlink handler, connect the handler and open channel"""
        logger.info('Starting XlinkSimulator initialization.')
        while self.myXLinkPClib.XLinkInitialize(byref(self.ghandler)) is not X_LINK_SUCCESS:
            pass
        while self.myXLinkPClib.XLinkConnect(byref(self.XlinkHandler)) is not X_LINK_SUCCESS:
            pass
        logger.debug('XLinkConnect done.')
        while self.myXLinkPClib.XLinkOpenChannel(byref(self.XlinkHandler), self.channelId,
                                                 self.operationType,
                                                 self.DATA_FRAGMENT_SIZE, 0) is not X_LINK_SUCCESS:
            pass
        logger.debug('XLinkOpenChannel done. Channel ID - ' + str(self.channelId.value))
        logger.info('XlinkSimulator initialization done.')

    def _listen_to_channel(self):
        """Listen the channel and waiting for incoming message"""
        while self.running:
            message = POINTER(c_char)()
            size = c_uint(0)
            status = self.myXLinkPClib.XLinkReadData(byref(self.XlinkHandler), self.channelId,
                                                     byref(message),
                                                     byref(size))
            if status is not X_LINK_SUCCESS:
                logger.error('Failed to write the message to the device.')
                break

            if size != 0:
                logger.info('Received message size ' + str(size.value) + '. Message is:')
                message_combined = ''
                for i in range(size.value):
                    message_combined = message_combined + \
                                       message[i].decode('utf-8', errors='replace')  # type: ignore
                    if i == (int(size.value) - 1):
                        logger.info('%s', str(message_combined))
                        if self.receive_callback_method is not None:
                            logger.info('Receive callback method exist. Call the method.')
                            self.receive_callback_method(message_combined)

            status = self.myXLinkPClib.XLinkReleaseData(
                byref(self.XlinkHandler), self.channelId, message)
            if status is not X_LINK_SUCCESS:
                logger.error('XLinkReadData ARM release data failed.')
                break

    def receive_file(self, file_save_path):
        """Receive update file and save it to the local repository.

        @param file_save_path: local path to save the update file
        """
        logger.info("Switch to receive file mode.")
        message = POINTER(c_char)()
        size = c_uint(0)
        # Receive file name
        status = self.myXLinkPClib.XLinkReadData(
            byref(self.XlinkHandler), self.channelId, byref(message), byref(size))
        file_name = ""
        for i in range(size.value):
            file_name = file_name + message[i].decode('utf-8', errors='strict')  # type: ignore

        # Receive update file
        logger.info("Receiving file. Please wait......")
        status = self.myXLinkPClib.XLinkReleaseData(
            byref(self.XlinkHandler), self.channelId, message)
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkReadData release data failed.')

        with open(file_save_path + "/" + file_name, 'wb') as update_file:
            status = self.myXLinkPClib.XLinkReadData(
                byref(self.XlinkHandler), self.channelId, byref(message), byref(size))
            for i in range(size.value):
                progress = self.receive_file_progress(i, int(size.value))
                if progress:
                    logger.info("Receiving file size " + str(progress) + "%")
                update_file.write(message[i])  # type: ignore

        status = self.myXLinkPClib.XLinkReleaseData(
            byref(self.XlinkHandler), self.channelId, message)
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkReadData release data failed.')
        logger.info("Receive file complete. File size: %s", str(size.value))
        logger.info("File stored at: %s", file_save_path + file_name)

        return file_name, status

    def receive_file_progress(self, current_size, total_size):
        """Calculate the progress of receiving file

        @param current_size: current received file size
        @param total_size: total file size
        """
        if current_size == int(total_size * 0.2):
            return 20
        if current_size == int(total_size * 0.4):
            return 40
        if current_size == int(total_size * 0.6):
            return 60
        if current_size == int(total_size * 0.8):
            return 80
        if current_size == int(total_size * 0.99):
            return 99
        return None

    def receive(self):
        """start to listen the receive channel"""
        self.listen_thread.start()

    def send(self, message):
        """Send the message through xlink write data API

        @param message: message to be sent
        """
        status = self.myXLinkPClib.XLinkWriteData(byref(self.XlinkHandler), self.channelId,
                                                  message.encode('utf8', errors='replace'),
                                                  len(message.encode('utf8', errors='strict')))
        logger.info('Sending message:')
        logger.info(str(message))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')

    def send_file(self, file_path):
        """Send the file through xlink write data API

        @param file_path: location of file to be sent
        """
        message = "FILE"
        status = self.myXLinkPClib.XLinkWriteData(byref(self.XlinkHandler), self.channelId,
                                                  message.encode('utf8', errors='strict'),
                                                  len(message.encode('utf8', errors='strict')))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')
        sleep(1)
        file_name = file_path.rsplit('/')[-1]
        status = self.myXLinkPClib.XLinkWriteData(byref(self.XlinkHandler), self.channelId,
                                                  file_name.encode('utf8', errors='strict'),
                                                  len(file_name.encode('utf8', errors='strict')))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')
        sleep(1)
        with open(file_path, 'rb') as update_file:
            read_file = update_file.read()

        status = self.myXLinkPClib.XLinkWriteData(
            byref(self.XlinkHandler), self.channelId, read_file, len(read_file))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')

    def stop(self):
        """Stop to listen the channel, close and disconnect xlink"""
        logger.info('Stopping XlinkSimulator.')
        self.running = False
        self.myXLinkPClib.XLinkCloseChannel(byref(self.XlinkHandler), self.channelId)
        self.myXLinkPClib.XLinkDisconnect(byref(self.XlinkHandler))
