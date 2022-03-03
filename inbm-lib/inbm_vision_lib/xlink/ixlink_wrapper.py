"""
    Interface for XlinkWrapper

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import sys
import logging
import os
import typing
import time
from abc import ABC, abstractmethod

from ctypes import *
from math import ceil
from typing import Optional, Callable, Tuple

from inbm_vision_lib.constants import MAXIMUM_WRITE_DATA_RETRY, XLINK_FILE_TRANSFER_RATE, UNKNOWN

from ..constants import VISION, FIP_FILE, OS_IMAGE, SECURE_XLINK_LIB_PATH, SW_DEVICE_ID_PLATFORM_MASK, \
    SW_DEVICE_ID_PLATFORM_SHIFT, SW_DEVICE_ID_KMB, KMB, TBH

xlink_dev_type = c_int
XLinkError_t = c_int
channelId_t = c_int
dataAddr = c_char_p
xlink_prof_cfg = c_int
node = c_uint8
xLinkCallback_t = CFUNCTYPE(None, channelId_t, dataAddr)
(HOST_DEVICE, VPUID_DEVICE) = (0, 1)
(USB_VSC, USB_CDC, PCIE, IPC, NMB_OF_PROTOCOLS) = (0, 1, 2, 3, 4)
(X_LINK_SUCCESS, X_LINK_ALREADY_INIT, X_LINK_ALREADY_OPEN, X_LINK_COMMUNICATION_NOT_OPEN, X_LINK_COMMUNICATION_FAIL,
 X_LINK_COMMUNICATION_UNKNOWN_ERROR, X_LINK_DEVICE_NOT_FOUND, X_LINK_TIMEOUT, X_LINK_ERROR) = \
    (0, 1, 2, 3, 4, 5, 6, 7, 8)
(POWER_DEFAULT_NOMINAL_MAX, POWER_SUBNOMINAL_HIGH, POWER_MEDIUM, POWER_LOW, POWER_MIN, POWER_SUSPENDED) = \
    (0, 1, 2, 3, 4, 5)
(RXB_TXB, RXN_TXN, RXB_TXN, RXN_TXB) = (0, 1, 2, 3)
(IPC_INTERFACE, PCIE_INTERFACE, USB_INTERFACE, ETH_INTERFACE) = (0x0, 0x1, 0x2, 0x3)
(CHAN_CLOSED, CHAN_OPEN, CHAN_BLOCKED_READ, CHAN_BLOCKED_WRITE, CHAN_OPEN_PEER) = (0x0000, 0x0001, 0x0010, 0x0100,
                                                                                   0x1000)
(XLINK_DEV_OFF, XLINK_DEV_ERROR, XLINK_DEV_BUSY, XLINK_DEV_RECOVERY, XLINK_DEV_READY) = (0, 1, 2, 3, 4)
#(NOTIFY_DEVICE_DISCONNECTED, NOTIFY_DEVICE_CONNECTED, NUM_EVENT_TYPE) = (0, 1, 2)
(NOTIFY_DEVICE_DISCONNECTED, NUM_EVENT_TYPE) = (0, 1)

logger = logging.getLogger(__name__)


class xlink_global_handle(Structure):
    """Struct of XLinkGlobalHandler_t"""
    _fields_ = [("loglevel", c_int),
                ("prof_cfg", xlink_prof_cfg)]


class xlink_handle(Structure):
    """Struct of XLinkHandler_t"""
    _fields_ = [("sw_device_id", c_uint32),
                ("dev_type", xlink_dev_type)]


class XLinkProf_t(Structure):
    """Struct of XLinkProf_t"""
    _fields_ = [("totalReadTime", c_float),
                ("totalWriteTime", c_float),
                ("totalReadBytes", c_ulong),
                ("totalWriteBytes", c_ulong),
                ("totalBootCount", c_ulong),
                ("totalBootTime", c_float)]


class XlinkWrapperException(Exception):
    """Class exception Module."""
    pass


class IXlinkWrapper(ABC):
    """Interface for Xlink Wrapper classes

    @param xlink_library_path: Path to the xlink library
    @param receive_callback: Callback for receiving messages over xlink
    @param channel_id: Channel used for xlink communication
    @param global_handler: Xlink global handler
    @param data_size:
    @param xlink_handler:
    @param pcie_num: PCIE Number for Xlink channel
    """

    def __init__(self, xlink_library_path: str, receive_callback: Callable, channel_id, global_handler, data_size,
                 xlink_handler, pcie_num: int, async_cb=None) -> None:
        self._agent = sys.argv[0].split('/')[-1]
        self._xlink_library = CDLL(xlink_library_path)
        self._receive_callback = receive_callback
        self._channel_id = channelId_t(channel_id)
        self._global_handler = global_handler
        self._operation_type = RXB_TXB
        self._data_size = data_size
        self._xlink_handler = xlink_handler
        self.xlink_init_status_success = False
        self._xlink_pcie_num = pcie_num
        self.platform_type = check_platform_type(self._xlink_pcie_num)
        self._running = True
        self._async_cb = async_cb

    @abstractmethod
    def send(self, message: str) -> None:
        """Send the message through xlink write data API

        @param message: message to be sent
        """
        pass

    @abstractmethod
    def receive(self, message: str) -> None:
        """Receive message through xlink API

        @param message: message received
        """
        pass

    @abstractmethod
    def start(self) -> None:
        """start to listen the receive channel"""

        pass

    @abstractmethod
    def stop(self, disconnect: bool = False) -> None:
        """Stop to listen the channel, close and disconnect xlink"""

        pass

    @abstractmethod
    def get_init_status(self) -> bool:
        """ Get the initialization status

        @return: boolean representing initialization status
        """
        pass

    @abstractmethod
    def receive_file(self, file_save_path: str) -> str:
        """Receive update file and save it to the local repository.

        @param file_save_path: local path to save the update file
        """
        pass

    @abstractmethod
    def send_file(self, file_path: str) -> None:
        """Send the message through xlink write data API

        @param file_path: location of file to be sent
        """

        pass

    @abstractmethod
    def get_xlink_device_status(self) -> int:
        """ Check the xlink device status.

            XLINK_DEV_OFF = 0,      // device is off
            XLINK_DEV_ERROR,        // device is busy and not available
            XLINK_DEV_BUSY,         // device is available for use
            XLINK_DEV_RECOVERY,     // device is in recovery mode
            XLINK_DEV_READY         // device HW failure is detected

            @return: status of xlink device
        """
        pass

    @abstractmethod
    def boot_device(self) -> None:
        """ Call xlink API to boot the device.
            Vision-agent will boot the device. No current support to boot VPU FW from node.
        """
        if self._agent == VISION:
            self._boot_device(FIP_FILE)
            time.sleep(1)
            self._boot_device(OS_IMAGE)
        else:
            logger.debug("Skip boot device.")

    @abstractmethod
    def reset_device(self) -> None:
        """Call xlink API to reset the device"""
        if self._agent == VISION:
            logger.debug("Reset device.")
            status = self._xlink_library.xlink_reset_device(byref(self._xlink_handler))
            if status is not X_LINK_SUCCESS:
                logger.error(f'Reset_device failed - {status}')
        else:
            logger.debug("Skip Reset device.")

    @staticmethod
    def _check_directory(path: str) -> None:
        if not os.path.exists(path):
            raise XlinkWrapperException("Directory to send/receive file via xlink does not exist.")

        if os.path.islink(path):
            raise XlinkWrapperException("Directory to send/receive file via xlink is a symlink.  This is not allowed "
                                        "for security reasons.")

    @staticmethod
    def _check_status(status: int, error_msg: str) -> None:
        if status is not X_LINK_SUCCESS:
            raise XlinkWrapperException(error_msg)

    def get_chunk_message(self, file_path: str) -> Tuple[str, int, int]:
        """Get message chunk

        @param file_path: path to message
        @return (str, int, int) number of the chunk, chunk number, size
        """
        transfer_size = int(self._data_size / 10 * XLINK_FILE_TRANSFER_RATE)
        file_size = os.path.getsize(file_path)
        number_of_chunk = ceil(file_size / transfer_size)
        logger.debug(file_size)
        logger.debug(transfer_size)
        return str(number_of_chunk), number_of_chunk, transfer_size

    def _register_async_callback(self) -> None:
        """Register callback to the xlink async for device disconnect/reconnect notification"""
        event_list = (c_uint32 * NUM_EVENT_TYPE)()
        for num in range(len(event_list)):
            event_list[num] = c_uint32(num)
        status = self._xlink_library.xlink_register_device_event(byref(self._xlink_handler),
                                                                 event_list,
                                                                 NUM_EVENT_TYPE,
                                                                 self._async_cb
                                                                 )
        if status is not X_LINK_SUCCESS:
            logger.error(f'Failed to register for xlink device event - {status}')
        else:
            logger.debug('Registered async callback for {0}.'.format(
                self._xlink_handler.sw_device_id))

    def _unregister_async_callback(self):
        """Unregister all device event from xlink"""
        event_list = (c_uint32 * NUM_EVENT_TYPE)()
        for num in range(len(event_list)):
            event_list[num] = c_uint32(num)
        status = self._xlink_library.xlink_unregister_device_event(byref(self._xlink_handler),
                                                                   event_list,
                                                                   NUM_EVENT_TYPE
                                                                   )
        if status is not X_LINK_SUCCESS:
            logger.error(f'Failed to unregister for xlink device event - {status}')

    def _write_data_via_unsecured(self, message: str):

        status = self._xlink_library.xlink_write_data(byref(self._xlink_handler), self._channel_id,
                                                      message.encode('utf8'),
                                                      len(message.encode('utf8')))
        IXlinkWrapper._check_status(status, 'XLinkWriteData data failed.')

    def write_file_via_unsecured(self, file_path: str) -> None:
        """Writes a file using unsecured xlink

        @param file_path: path of the file to be sent
        """
        self._check_directory(file_path)
        self._write_data_via_unsecured("FILE")
        time.sleep(0.2)

        file_name = file_path.rsplit('/')[-1]
        logger.debug("sending file via xlink: " + file_name)
        self._write_data_via_unsecured(file_name)
        time.sleep(0.2)

        chunk_message, number_of_chunk, transfer_size = self.get_chunk_message(file_path)
        self._write_data_via_unsecured(chunk_message)
        time.sleep(0.2)

        if number_of_chunk > 1:
            with open(file_path, 'rb') as update_file:
                for num in range(number_of_chunk):
                    if num == number_of_chunk - 1:
                        read_file = update_file.read()
                    else:
                        read_file = update_file.read(transfer_size)
                    retry = 0
                    while self._running:
                        status = self._xlink_library.xlink_write_data(
                            byref(self._xlink_handler), self._channel_id, read_file, len(read_file))
                        time.sleep(0.1)
                        if status is X_LINK_SUCCESS:
                            break
                        elif retry > MAXIMUM_WRITE_DATA_RETRY:
                            IXlinkWrapper._check_status(status, 'XLinkWriteData data failed.')
                        else:
                            retry += 1
                            logger.debug(
                                f'Write failed. status - {status}. Retry number = {retry}')
                            time.sleep(5)

        else:
            with open(file_path, 'rb') as update_file:
                read_file = update_file.read()
            status = self._xlink_library.xlink_write_data(
                byref(self._xlink_handler), self._channel_id, read_file, len(read_file))
            IXlinkWrapper._check_status(status, 'XLinkWriteData data failed.')

    def get_device_id(self) -> int:
        """Get the sw device id"""
        return self._xlink_handler.sw_device_id

    def get_platform_type(self) -> str:
        """Get the platform type"""
        return self.platform_type

    def _xlink_release_data(self) -> None:
        """Release xlink data buffer"""
        status = self._xlink_library.xlink_release_data(
            byref(self._xlink_handler), self._channel_id, None)

        self._check_status(status, 'XLink release data failed.')

    def _boot_device(self, file_path: str) -> None:
        # (What is the difference between this boot device and above?  Can they be combined?)
        logger.debug(f"boot device with {file_path}")
        status = self._xlink_library.xlink_boot_device(
            byref(self._xlink_handler), file_path.encode('utf8'))
        if status is not X_LINK_SUCCESS:
            logger.error('boot_device with {} failed - {}'.format(file_path, str(status)))


def check_platform_type(sw_device_id: typing.Union[int, str]) -> str:
    """Check the platform type based on b7 to b4 in sw device id.

       0000b – KMB device
       0001b – THB Prime device with 2 compute slices
       0010b – THB Standard device with 4 compute slices
       0011b – OYB device
       0100b – MTL device
       0101b – STF device
       Rest of the values – reserved for future or not used

    @param sw_device_id: unique sw device id obtained from xlink
    @return: platform type
    """
    logger.debug("sw_device_id: {}".format(str(sw_device_id)))
    try:
        platform_type = (int(sw_device_id) >> SW_DEVICE_ID_PLATFORM_SHIFT) & SW_DEVICE_ID_PLATFORM_MASK
        logger.debug("platform type: {}".format(str(platform_type)))
        return KMB if platform_type == SW_DEVICE_ID_KMB else TBH
    except ValueError:
        return UNKNOWN


def receive_file_progress(current_size: int, total_size: int) -> Optional[int]:
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


def _is_xlink_secure_exist():
    return True if os.path.exists(SECURE_XLINK_LIB_PATH) else False
