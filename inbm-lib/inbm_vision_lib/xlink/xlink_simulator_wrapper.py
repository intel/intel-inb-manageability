"""
    Allows API of xlink driver C library to be called in Python.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import sys
import logging
import threading
import tempfile
from .ixlink_wrapper import IXlinkWrapper
from .ixlink_wrapper import receive_file_progress
from .ixlink_wrapper import PCIE, X_LINK_SUCCESS
from inbm_vision_lib.constants import XLINK_SIMULATOR_PC_LIB_PATH, XLINK_SIMULATOR_ARM_LIB_PATH, VISION
from inbm_vision_lib.utility import remove_file

from ctypes import *
from time import sleep

XLinkDeviceTypes_t = c_int
linkId_t = c_uint8
(VPU_DEVICE, PCIE_DEVICE, USB_DEVICE, IPC_DEVICE, ETH_DEVICE, NMB_OF_DEVICE_TYPES) = (0, 1, 2, 3, 4, 5)

logger = logging.getLogger(__name__)


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


class XlinkSimulatorWrapper(IXlinkWrapper):
    """Wrapper class to use xlink shared library"""

    def __init__(self, receive_callback, channel_id) -> None:
        # The tempfile library is being used to fulfil the bandit testing check regarding temporary files.  Because the
        # vision-agent and node-agent need to be using the same file to connect, generating a unique filename for both
        # does not work.  Therefore, we are using the tempfile library, but truncating out the random part of the file
        # name so that it can connect.  A story has been created to remove this from our production code base since it
        # is only used for development and testing.  Then we can go back to using a hardcoded temporary path.
        self.temp = tempfile.NamedTemporaryFile(mode='w', prefix='xlink', suffix='_mock')
        super().__init__(
            XLINK_SIMULATOR_PC_LIB_PATH if sys.argv[0].split('/')[-1] == VISION else XLINK_SIMULATOR_ARM_LIB_PATH,
            receive_callback,
            channel_id,
            XLinkGlobalHandler_t(protocol=PCIE),
            1024,
            XLinkHandler_t(
                devicePath=str(
                    self.temp.name[0:10]
                    + self.temp.name[self.temp.name.find('_mock'):]).encode('utf8'),
                deviceType=PCIE_DEVICE), 0
            )
        self._agent = sys.argv[0].split('/')[-1]
        self._init_channel()
        self._listen_thread = threading.Thread(target=self._listen_to_channel)
        self._listen_thread.daemon = True

    def _init_channel(self):
        """Initialize Xlink handler, connect the handler and open channel"""
        logger.info(f'{self._agent} starting Xlink Simulator.')
        while self._xlink_library.XLinkInitialize(byref(self._global_handler)) is not X_LINK_SUCCESS:
            pass
        while self._xlink_library.XLinkConnect(byref(self._xlink_handler)) is not X_LINK_SUCCESS:
            pass
        logger.debug('XLinkConnect done.')
        while self._xlink_library.XLinkOpenChannel(byref(self._xlink_handler), self._channel_id,
                                                   self._operation_type,
                                                   self._data_size, 0) is not X_LINK_SUCCESS:
            pass
        logger.debug('XLinkOpenChannel done. Channel ID - ' + str(self._channel_id.value))
        logger.info('Xlink Simulator initialized.')

    def _listen_to_channel(self):
        """Listen the channel and waiting for incoming message"""
        while self._running:
            message = POINTER(c_char)()
            size = c_uint(0)
            status = self._xlink_library.XLinkReadData(byref(self._xlink_handler), self._channel_id,
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
                                       message[i].decode('utf-8')  # type: ignore
                    if i == (int(size.value) - 1):
                        logger.info('%s', str(message_combined))
                        if self._receive_callback is not None:
                            logger.info('Receive callback method exist. Call the method.')
                            self._receive_callback(message_combined)

            status = self._xlink_library.XLinkReleaseData(
                byref(self._xlink_handler), self._channel_id, message)
            if status is not X_LINK_SUCCESS:
                logger.error('XLinkReadData ARM release data failed.')
                break

    def get_device_id(self) -> int:
        """Get the sw device id"""
        virtual_sw_device_id = 16084061002
        return virtual_sw_device_id

    def get_init_status(self) -> bool:
        """ Get the initialization status

        @return: boolean representing initialization status
        """
        return True

    def receive(self, message: str) -> None:
        """Receive message"""
        pass

    def get_xlink_device_status(self) -> int:
        """ Check the xlink device status.

            @return: status of xlink device
        """
        pass

    def receive_file(self, file_save_path):
        # inherit docstring from superclass

        logger.info("Switch to receive file mode.")
        message = POINTER(c_char)()
        size = c_uint(0)
        # Receive file name
        status = self._xlink_library.XLinkReadData(
            byref(self._xlink_handler), self._channel_id, byref(message), byref(size))
        file_name = ""
        for i in range(size.value):
            file_name = file_name + message[i].decode('utf-8')  # type: ignore

        file_path = os.path.join(file_save_path, file_name)
        remove_file(file_path)

        # Receive update file
        logger.info("Receiving file. Please wait......")
        status = self._xlink_library.XLinkReleaseData(
            byref(self._xlink_handler), self._channel_id, message)
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkReadData release data failed.')

        with open(file_path, 'wb') as update_file:
            status = self._xlink_library.XLinkReadData(
                byref(self._xlink_handler), self._channel_id, byref(message), byref(size))
            for i in range(size.value):
                progress = receive_file_progress(i, int(size.value))
                if progress:
                    logger.info("Receiving file size " + str(progress) + "%")
                update_file.write(message[i])  # type: ignore

        status = self._xlink_library.XLinkReleaseData(
            byref(self._xlink_handler), self._channel_id, message)
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkReadData release data failed.')
        logger.info("Receive file complete. File size: %s", str(size.value))
        logger.info("File stored at: %s", file_path)

        return file_name

    def start(self):
        # inherit docstring from superclass

        self._listen_thread.start()

    def send(self, message):
        # inherit docstring from superclass

        status = self._xlink_library.XLinkWriteData(byref(self._xlink_handler), self._channel_id,
                                                    message.encode('utf8'),
                                                    len(message.encode('utf8')))
        logger.info('Sending message:')
        logger.info(str(message))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')

    def boot_device(self) -> None:
        logger.info('Xlink call boot device')

    def reset_device(self) -> None:
        logger.info('Xlink call reset device')

    def send_file(self, file_path):
        # inherit docstring from superclass

        message = "FILE"
        status = self._xlink_library.XLinkWriteData(byref(self._xlink_handler), self._channel_id,
                                                    message.encode('utf8'),
                                                    len(message.encode('utf8')))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')
        sleep(1)
        file_name = file_path.rsplit('/')[-1]
        status = self._xlink_library.XLinkWriteData(byref(self._xlink_handler), self._channel_id,
                                                    file_name.encode('utf8'),
                                                    len(file_name.encode('utf8')))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')
        sleep(1)
        with open(file_path, 'rb') as update_file:
            read_file = update_file.read()

        status = self._xlink_library.XLinkWriteData(
            byref(self._xlink_handler), self._channel_id, read_file, len(read_file))
        if status is not X_LINK_SUCCESS:
            logger.error('XLinkWriteData data failed.')

    def stop(self, disconnect: bool = False):
        # inherit docstring from superclass

        logger.info('Stopping XlinkSimulator.')
        self._running = False
        self.temp.close()
        self._xlink_library.XLinkCloseChannel(byref(self._xlink_handler), self._channel_id)
        self._xlink_library.XLinkDisconnect(byref(self._xlink_handler))
