"""
    Allows API of xlink driver C library to be called in Python.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import threading
import os
from ctypes import *
from threading import Lock
from typing import Callable, Tuple

import time
from inbm_vision_lib.constants import SECURE_XLINK_LIB_PATH, XLINK_LIB_PATH, NODE_BUFFER_TIMEOUT, \
    VISION_BUFFER_TIMEOUT, XLINK_SECURE_DATA_SIZE, MAXIMUM_STORE_FILE_SIZE, XLINK_FILE_TRANSFER_RATE, \
    SECURE_XLINK_PROVISION_LIB_PATH, MINIMUM_GUID_LENGTH, MAXIMUM_GUID_BUFFER
from ..constants import VISION

from .ixlink_wrapper import IXlinkWrapper, xlink_handle, xlink_prof_cfg, HOST_DEVICE, PCIE, X_LINK_SUCCESS, \
    XlinkWrapperException

logger = logging.getLogger(__name__)


class xlink_global_handle(Structure):
    """Struct of XLinkGlobalHandler_t"""
    _fields_ = [("loglevel", c_int),
                ("prof_cfg", xlink_prof_cfg)]


class XlinkSecureWrapper(IXlinkWrapper):
    """Wrapper class to use secured xlink shared library

    @param receive_callback: Callback for receiving messages over xlink
    @param channel_id: Channel used for xlink communication
    @param pcie_num: PCIe Channel for xlink channel
    @param is_boot_dev: True if xlink boot device API to be called; otherwise, False
    """

    def __init__(self, receive_callback: Callable, channel_id: int, pcie_num: int, is_boot_dev: bool) -> None:
        super().__init__(XLINK_LIB_PATH,
                         receive_callback,
                         channel_id,
                         xlink_global_handle(prof_cfg=PCIE),
                         XLINK_SECURE_DATA_SIZE,
                         xlink_handle(dev_type=HOST_DEVICE),
                         pcie_num,
                         async_cb=None)

        self._xlink_handler.sw_device_id = self._xlink_pcie_num
        self._is_boot_dev = is_boot_dev
        # Xlink secure only support part of APIs, need to use regular xlink library for other APIs
        self._secure_xlink = CDLL(SECURE_XLINK_LIB_PATH)
        self._open_channel_lock = Lock()
        self._read_data_lock = Lock()
        self._write_data_lock = Lock()
        self.init_thread = threading.Thread(target=self._init_channel)
        self.init_thread.daemon = True
        self.init_thread.start()
        self._listen_thread = threading.Thread(target=self._listen_to_channel)
        self._listen_thread.daemon = True

    def _init_channel(self):
        """Initialize Xlink handler, connect the handler and open channel"""
        logger.debug('Start Xlink Secure initialization.')
        self.xlink_init_status_success = False
        while self._running:
            logger.debug('waiting xlink_secure_initialize...')
            status = self._secure_xlink.xlink_secure_initialize()
            if status is X_LINK_SUCCESS:
                break
            time.sleep(1)
        logger.debug('xlink_secure_initialize complete.')

        logger.debug(f"PCIE Number: {self._xlink_pcie_num}")

        if self._is_boot_dev:
            self.boot_device()
        xlink_handler_p = byref(self._xlink_handler)
        logger.debug(
            'xlink_connect start connecting... Waiting the connection...')
        while self._running:
            status = self._secure_xlink.xlink_secure_connect(xlink_handler_p)
            if status is X_LINK_SUCCESS:
                logger.debug('xlink_connect pass.')
                logger.debug('xlink_open_channel. Channel ID - ' +
                             str(self._channel_id.value))
                break
            logger.debug(
                'xlink_connect start connecting... Waiting the connection...')
            time.sleep(1)

        while self._running:
            if self._open_channel_lock.acquire():
                timeout = VISION_BUFFER_TIMEOUT if self._agent == VISION else NODE_BUFFER_TIMEOUT
                try:
                    status = self._secure_xlink.xlink_secure_open_channel(xlink_handler_p, self._channel_id,
                                                                          self._operation_type,
                                                                          self._data_size, timeout * 1000)

                finally:
                    self._open_channel_lock.release()
                if status is X_LINK_SUCCESS:
                    logger.debug('Opened secure Xlink Channel.  Channel ID - ' +
                                 str(self._channel_id.value))
                    # Wait 5 seconds for xlink to stabilize
                    time.sleep(5)
                    self.xlink_init_status_success = True
                    logger.info('Xlink Secure initialization complete.')
                    break
            else:
                pass
            time.sleep(1)

    def boot_device(self) -> None:
        """ Call xlink API to boot the device.
            vision-agent will boot the device. Currently there is no support to boot VPU FW from node.
        """
        super().boot_device()

    def reset_device(self) -> None:
        """Call xlink API to reset the device"""
        super().reset_device()

    def _register_callback(self) -> None:
        """Register callback to the xlink"""
        status = self._xlink_library.xlink_data_available_event(byref(self._xlink_handler), self._channel_id,
                                                                c_void_p())
        if status is not X_LINK_SUCCESS:
            logger.error('Xlink Data Event Failed - %s', str(status))

        status = self._xlink_library.xlink_data_consumed_event(byref(self._xlink_handler), self._channel_id,
                                                               c_void_p())
        if status is not X_LINK_SUCCESS:
            logger.error('Xlink Data Event Failed - %s ', str(status))
        logger.debug("xlink callback register pass.")

    def _listen_to_channel(self):
        """Listen the channel and waiting for incoming message"""
        # Waiting xlink initialization complete
        s_buffer = create_string_buffer(self._data_size)
        message = POINTER(c_char)(s_buffer)  # type: ignore
        while self._running and not self.xlink_init_status_success:
            time.sleep(1)

        while self._running:
            size = c_uint32(0)
            while self._running and size.value == 0 and self._read_data_lock.acquire():
                try:
                    self._secure_xlink.xlink_secure_read_data(byref(self._xlink_handler), self._channel_id,
                                                              byref(message),
                                                              byref(size))
                    time.sleep(1)
                finally:
                    self._read_data_lock.release()

            if size.value != 0:
                logger.info('Received message size ' +
                            str(size.value) + '. Message is:')
                message_combined = ''

                for i in range(size.value):
                    message_combined = message_combined + \
                        message[i].decode('utf-8')  # type: ignore
                    if i == (int(size.value) - 1):
                        logger.info('%s', str(message_combined))
                        self._xlink_release_data()
                        if self._receive_callback is not None:
                            logger.info(
                                'Receive callback method exist. Call the method.')
                            self._receive_callback(message_combined)

    def receive_file(self, file_save_path: str) -> str:
        """Receive update file and save it to the local repository.

        @param file_save_path: local path to save the update file
        @return : (str) received file name
        """
        super()._check_directory(file_save_path)
        logger.debug("Switch to receive file mode.")
        s_buffer = create_string_buffer(self._data_size)
        message = POINTER(c_char)(s_buffer)  # type: ignore
        size = c_uint32(0)

        # Receive file name
        while size.value == 0 and self._running:
            self._secure_xlink.xlink_secure_read_data(byref(self._xlink_handler), self._channel_id, byref(message),
                                                      byref(size))
            time.sleep(1)

        file_name = ""
        for i in range(size.value):
            file_name = file_name + message[i].decode('utf-8')  # type: ignore

        logger.debug(f"Receive file name - {file_name}")
        file_path = os.path.join(file_save_path, file_name)
        self._xlink_release_data()

        # Receive number of chunk
        size = c_uint32(0)
        while size.value == 0 and self._running:
            self._secure_xlink.xlink_secure_read_data(byref(self._xlink_handler), self._channel_id, byref(message),
                                                      byref(size))
            time.sleep(1)

        chunk_message = ""
        for i in range(size.value):
            chunk_message = chunk_message + \
                message[i].decode('utf-8')  # type: ignore
        num_of_chunk = int(chunk_message)
        logger.debug(f"Number of chunk - {chunk_message}")
        self._xlink_release_data()

        # Receive update file
        logger.info("Receiving file. Please wait......")

        # Reset size for receiving file
        with open(file_path, 'wb') as update_file:
            if num_of_chunk > 1:
                file_collect = b''
                for num in range(num_of_chunk):
                    logger.info("{}/{}".format(num, num_of_chunk - 1))
                    size = c_uint32(0)
                    while size.value == 0 and self._running:
                        self._secure_xlink.xlink_secure_read_data(byref(self._xlink_handler), self._channel_id,
                                                                  byref(
                                                                      message),
                                                                  byref(size))
                        time.sleep(0.5)
                    file_collect = file_collect + \
                        message[:size.value]  # type: ignore
                    # Write to file if file stored in memory larger than the limit or it is the last chunk of file.
                    if len(file_collect) > MAXIMUM_STORE_FILE_SIZE or num == (num_of_chunk - 1):
                        logger.debug("write to file")
                        update_file.write(file_collect)  # type: ignore
                        update_file.flush()
                        file_collect = b''
                    if num != (num_of_chunk - 1):
                        self._xlink_release_data()
            else:
                size = c_uint32(0)
                while size.value == 0 and self._running:
                    self._secure_xlink.xlink_secure_read_data(byref(self._xlink_handler), self._channel_id,
                                                              byref(message),
                                                              byref(size))
                for i in range(size.value):
                    # Temporary disable the progress bar as it causes slowness in simics.
                    # progress = receive_file_progress(i, int(size.value))
                    # if progress:
                    #    logger.info("Receiving file size " + str(progress) + "%")
                    update_file.write(message[i])  # type: ignore
        self._xlink_release_data()
        logger.info("Receive file complete. File size: %i",
                    os.path.getsize(file_path))
        logger.debug("File stored at: %s", file_path)

        return file_name

    def get_init_status(self) -> bool:
        """ Get the initialization status

        @return: boolean representing initialization status
        """
        return self.xlink_init_status_success

    def start(self) -> None:
        """start to listen the receive channel"""
        self._listen_thread.start()

    def send(self, message: str) -> None:
        """Send the message through xlink write data API

        @param message: message to be sent
        """
        # Waiting xlink initialization complete
        while self._running and not self.xlink_init_status_success:
            time.sleep(0.1)
        if self.xlink_init_status_success:
            logger.debug('Sending message: ' + str(message))
            self._write_data_via_secured(message)
        else:
            logger.info('Stop XLinkWriteData')

    def receive(self, message: str) -> None:
        """Receive message"""
        pass

    def get_xlink_device_status(self) -> int:
        """ Check the xlink device status.
        
            @return: status of xlink device
        """
        pass

    def _write_data_via_secured(self, message: str):
        while self._running and self._write_data_lock.acquire():
            try:
                status = self._secure_xlink.xlink_secure_write_data(byref(self._xlink_handler), self._channel_id,
                                                                    message.encode(
                                                                        'utf8'),
                                                                    len(message.encode('utf8')))
            finally:
                self._write_data_lock.release()
                break

        super()._check_status(status, 'XLinkWriteData data failed.')

    def send_file(self, file_path: str) -> None:
        # inherit docstring from superclass
        super()._check_directory(file_path)
        self._write_data_via_secured("FILE")

        time.sleep(1)
        file_name = file_path.rsplit('/')[-1]
        logger.debug("sending file via xlink: " + file_name)
        self._write_data_via_secured(file_name)
        time.sleep(1)

        chunk_message, number_of_chunk, transfer_size = self.get_chunk_message(
            file_path)
        self._write_data_via_secured(chunk_message)
        time.sleep(1)

        if number_of_chunk > 1:
            with open(file_path, 'rb') as update_file:
                for num in range(number_of_chunk):
                    if num == number_of_chunk - 1:
                        read_file = update_file.read()
                    else:
                        read_file = update_file.read(transfer_size)
                    status = self._secure_xlink.xlink_secure_write_data(
                        byref(self._xlink_handler), self._channel_id, read_file, len(read_file))
                    super()._check_status(status, 'XLinkWriteData data failed.')
                    # For larger file size, increase the waiting time due to xlink instability
                    time.sleep(0.01)
        else:
            with open(file_path, 'rb') as update_file:
                read_file = update_file.read()
            status = self._secure_xlink.xlink_secure_write_data(
                byref(self._xlink_handler), self._channel_id, read_file, len(read_file))
            super()._check_status(status, 'XLinkWriteData data failed.')

    def _xlink_release_data(self) -> None:
        """Release xlink data buffer"""
        status = self._secure_xlink.xlink_secure_release_data(
            byref(self._xlink_handler), self._channel_id, None)

        super()._check_status(status, 'XLink release data failed.')

    @staticmethod
    def get_guid(sw_device_id: int) -> Tuple[str, str]:
        """Call secure xlink API to get specific node's GUID and SVN.

        @param sw_device_id: sw_device_id to be checked
        @return: GUID of node, SVN of node
        """
        logger.debug(f"get_guid: sw_device_id: {sw_device_id}")
        try:
            guid = create_string_buffer(MAXIMUM_GUID_BUFFER)
            guid_len = c_uint32(MINIMUM_GUID_LENGTH)
            svn = c_uint32(0)
            _secure_xlink_provision = CDLL(SECURE_XLINK_PROVISION_LIB_PATH)

            # Get GUID
            status = _secure_xlink_provision.secure_xlink_provision_read_guid(
                sw_device_id, guid, guid_len)
            IXlinkWrapper._check_status(status, f'Secure xlink read GUID failed with status {status}. '
                                                f'SWID - {sw_device_id}')
            logger.debug(f"GUID = {guid.value.decode('utf-8')}")
            # Get SVN
            status = _secure_xlink_provision.secure_xlink_provision_read_svn(
                sw_device_id, byref(svn))
            IXlinkWrapper._check_status(status, f'Secure xlink read GUID failed with status {status}. '
                                                f'SWID - {sw_device_id}')
            logger.debug(f"svn = {str(svn.value)}")
            return guid.value.decode('utf-8'), str(svn.value)
        except (XlinkWrapperException, OSError, TypeError, SystemError) as e:
            logger.error(
                f'Error retrieving GUID for node with device_id: {sw_device_id}.  Error: {e}')

        return "0", "0"

    @staticmethod
    def is_provisioned(sw_device_id: int) -> bool:
        """Call secure xlink API to get node's provisioned status.

        @param sw_device_id: sw_device_id to be checked
        @return: True if provisioned. False if not provisioned.
        """
        try:
            _secure_xlink_provision = CDLL(SECURE_XLINK_PROVISION_LIB_PATH)
            provision_status = c_int(0)
            status = _secure_xlink_provision.secure_xlink_is_provisioned(
                sw_device_id, byref(provision_status))
            IXlinkWrapper._check_status(status, f'Secure xlink get provisioned status failed with status {status}. '
                                                f'SWID - {sw_device_id}')
            status = True if provision_status.value else False
            logger.debug(
                f"is_provisioned status of {str(sw_device_id)}: {status}")
            return status

        except (XlinkWrapperException, OSError, SystemError) as e:
            logger.error(str(e))

        return False

    def stop(self, disconnect: bool = False) -> None:
        # inherit docstring from superclass
        logger.debug('Stopping Xlink.')
        self._running = False
        while not self._open_channel_lock.acquire():
            time.sleep(0.1)
        logger.debug('Get Lock - open channel.')
        while not self._read_data_lock.acquire():
            time.sleep(0.1)
        logger.debug('Get Lock - read data.')
        while not self._write_data_lock.acquire():
            time.sleep(0.1)
        logger.debug('Get Lock - write data.')
        time.sleep(1)
        logger.debug('Close Xlink channel ID - ' + str(self._channel_id.value))
        self._secure_xlink.xlink_secure_close_channel(
            byref(self._xlink_handler), self._channel_id)
        if disconnect:
            # Wait 0.5s to let xlink fully close the channel before disconnecting it.
            time.sleep(0.5)
            logger.debug('Disconnect Xlink')
            self._secure_xlink.xlink_secure_disconnect(
                byref(self._xlink_handler))
