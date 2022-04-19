"""
    Allows API of xlink driver C library to be called in Python.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import threading
import os
from typing import Callable, Optional
from ctypes import *

import time
from inbm_vision_lib.constants import XLINK_LIB_PATH, MAXIMUM_STORE_FILE_SIZE, XLINK_DATA_SIZE, \
    XLINK_FILE_TRANSFER_RATE, NODE_BUFFER_TIMEOUT, VISION_BUFFER_TIMEOUT
from threading import Lock
from ..constants import VISION

from .ixlink_wrapper import IXlinkWrapper
from .ixlink_wrapper import HOST_DEVICE, PCIE, X_LINK_SUCCESS
from .ixlink_wrapper import xlink_global_handle, xlink_handle

logger = logging.getLogger(__name__)


class XlinkWrapper(IXlinkWrapper):
    """Wrapper class to use xlink shared library

    @param receive_callback: Callback for receiving messages over xlink
    @param channel_id: Channel used for xlink communication
    @param pcie_num: PCIE number used in connection
    @param is_boot_dev: true if xlink boot device API to be called
    """

    def __init__(self, receive_callback: Callable, channel_id: int, pcie_num: int, is_boot_dev: bool,
                 async_cb: Optional[Callable] = None):
        super().__init__(XLINK_LIB_PATH,
                         receive_callback,
                         channel_id,
                         xlink_global_handle(prof_cfg=PCIE),
                         XLINK_DATA_SIZE,
                         xlink_handle(dev_type=HOST_DEVICE),
                         pcie_num,
                         async_cb)
        self._xlink_handler.sw_device_id = self._xlink_pcie_num
        self._is_boot_dev = is_boot_dev
        self._open_channel_lock = Lock()
        self._read_data_lock = Lock()
        self._write_lock = Lock()
        self.init_thread = threading.Thread(target=self._init_channel)
        self.init_thread.start()
        self._listen_thread = threading.Thread(target=self._listen_to_channel)
        self._listen_thread.daemon = True

    def _init_channel(self):
        """Initialize Xlink handler, connect the handler and open channel"""
        logger.debug(f'{self._agent} start Xlink initialization.')
        self.xlink_init_status_success = False
        while self._running:
            status = self._xlink_library.xlink_initialize()
            if status is X_LINK_SUCCESS:
                break
            time.sleep(1)

        logger.debug(f"PCIE Number: {self._xlink_pcie_num}")

        if self._is_boot_dev:
            self.boot_device()
        xlink_handler_p = byref(self._xlink_handler)
        logger.debug('xlink_connect start connecting... Waiting the connection...')
        while self._running:
            status = self._xlink_library.xlink_connect(xlink_handler_p)
            if status is X_LINK_SUCCESS:
                logger.debug('xlink_connect pass.')
                logger.debug('xlink_open_channel. Channel ID - ' + str(self._channel_id.value))
                break
            logger.debug('xlink_connect start connecting... Waiting the connection...')
            time.sleep(1)

        if self._async_cb:
            self._register_async_callback()

        while self._running:
            if self._open_channel_lock.acquire():
                timeout = VISION_BUFFER_TIMEOUT if self._agent == VISION else NODE_BUFFER_TIMEOUT
                try:
                    status = self._xlink_library.xlink_open_channel(xlink_handler_p, self._channel_id,
                                                                    self._operation_type,
                                                                    self._data_size, timeout * 1000)

                finally:
                    self._open_channel_lock.release()
                if status is X_LINK_SUCCESS:
                    logger.debug('xlink_open_channel pass. Channel ID - ' +
                                 str(self._channel_id.value))
                    # Wait 5 seconds for xlink to stabilize
                    time.sleep(5)
                    self.xlink_init_status_success = True
                    logger.info('Xlink initialization complete.')
                    break
            else:
                pass
            time.sleep(1)

    def get_xlink_device_status(self) -> int:
        """ Check the xlink device status.

            XLINK_DEV_OFF = 0,      // device is off
            XLINK_DEV_ERROR,        // device is busy and not available
            XLINK_DEV_BUSY,         // device is available for use
            XLINK_DEV_RECOVERY,     // device is in recovery mode
            XLINK_DEV_READY         // device HW failure is detected

            @return: status of xlink device
        """
        device_status = c_int(0)
        #        logger.debug('Call xlink get device status for {0}'.format(
        #            str(self._xlink_handler.sw_device_id)))
        if self._running:
            status = self._xlink_library.xlink_get_device_status(
                byref(self._xlink_handler), byref(device_status))
            if status is not X_LINK_SUCCESS:
                logger.error('xlink_get device status failed - %s', str(status))
                device_status = c_int(-1)
        else:
            logger.debug('Closing xlink in progress. Will not disrupt it.')
            device_status.value = 4
        logger.debug('xlink device status for {} is {}'.format(
            str(self._xlink_handler.sw_device_id), str(device_status.value)))
        return device_status.value

    def boot_device(self) -> None:
        """ Call xlink API to boot the device.
            Only IA vision-agentboot the device. Not support boot VPU FW from node in current stage.
        """
        super().boot_device()

    def reset_device(self) -> None:
        """Call xlink API to reset the device"""
        super().reset_device()

    def _register_callback(self) -> None:
        """Register dummy callback to the xlink"""
        dummy_callback = c_void_p()
        status = self._xlink_library.xlink_data_available_event(byref(self._xlink_handler), self._channel_id,
                                                                dummy_callback)
        if status is not X_LINK_SUCCESS:
            logger.error('Xlink Data Event Failed - %s', str(status))

        status = self._xlink_library.xlink_data_consumed_event(byref(self._xlink_handler), self._channel_id,
                                                               dummy_callback)
        if status is not X_LINK_SUCCESS:
            logger.error('Xlink Data Event Failed - %s', str(status))
        logger.debug("xlink callback registered.")

    def _listen_to_channel(self):
        """Listen the channel and waiting for incoming message"""
        s_buffer = create_string_buffer(self._data_size)
        message = POINTER(c_char)(s_buffer)  # type: ignore
        # Waiting xlink initialization complete
        while self._running and not self.xlink_init_status_success:
            time.sleep(1)

        while self._running:
            size = c_uint32(0)
            while self._running and size.value == 0 and self._read_data_lock.acquire():
                try:
                    self._xlink_library.xlink_read_data(byref(self._xlink_handler), self._channel_id, byref(message),
                                                        byref(size))
                    time.sleep(0.1)
                finally:
                    self._read_data_lock.release()

            if size.value != 0:
                logger.info('Received message size ' + str(size.value) + '. Message is:')
                message_combined = ''

                for i in range(size.value):
                    message_combined = message_combined + \
                                       message[i].decode('utf-8')  # type: ignore
                    if i == (int(size.value) - 1):
                        logger.info('%s', str(message_combined))
                        self._xlink_release_data()
                        if self._receive_callback is not None:
                            logger.info('Receive callback method exist. Call the method.')
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
        while size.value == 0:
            self._xlink_library.xlink_read_data(byref(self._xlink_handler), self._channel_id, byref(message),
                                                byref(size))
        file_name = ""
        for i in range(size.value):
            file_name = file_name + message[i].decode('utf-8')  # type: ignore
        self._xlink_release_data()
        file_path = os.path.join(file_save_path, file_name)

        # Receive number of chunk
        size = c_uint32(0)
        while size.value == 0:
            self._xlink_library.xlink_read_data(byref(self._xlink_handler), self._channel_id, byref(message),
                                                byref(size))
        chunk_message = ""
        for i in range(size.value):
            chunk_message = chunk_message + message[i].decode('utf-8')  # type: ignore
        num_of_chunk = int(chunk_message)
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
                    while size.value == 0:
                        status = self._xlink_library.xlink_read_data(byref(self._xlink_handler), self._channel_id,
                                                                     byref(message),
                                                                     byref(size))

                    file_collect = file_collect + message[:size.value]  # type: ignore
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
                while size.value == 0:
                    status = self._xlink_library.xlink_read_data(byref(self._xlink_handler), self._channel_id,
                                                                 byref(message),
                                                                 byref(size))
                for i in range(size.value):
                    # Temporary disable the progress bar as it causes slowness in simics.
                    # progress = receive_file_progress(i, int(size.value))
                    # if progress:
                    #    logger.info("Receiving file size " + str(progress) + "%")
                    update_file.write(message[i])  # type: ignore

        self._xlink_release_data()
        logger.info("Receiving file size 100%.")
        logger.info("Receive file complete. File size: %i", os.path.getsize(file_path))
        logger.info("File stored at: %s", file_path)

        return file_name

    def get_init_status(self) -> bool:
        """ Get the initialization status

        @return: boolean representing initialization status
        """
        return self.xlink_init_status_success

    def start(self) -> None:
        """start to listen the receive channel"""
        self._listen_thread.start()

    def send(self, message) -> None:
        """Send the message through xlink write data API

        @param message: message to be sent
        """
        # Waiting xlink initialization complete
        while self._running and not self.get_init_status():
            time.sleep(1)

        if self.get_init_status() and self._running:
            logger.debug('Sending message: ' + str(message))
            while self._running and self._write_lock.acquire():
                try:
                    status = self._xlink_library.xlink_write_data(byref(self._xlink_handler), self._channel_id,
                                                                  message.encode('utf8'),
                                                                  len(message.encode('utf8')))
                    super()._check_status(status, 'XLinkWriteData data failed.')
                finally:
                    self._write_lock.release()
                    break
        else:
            logger.info('Stop XLinkWriteData')

    def receive(self, message: str) -> None:
        """Receive message"""
        pass

    def send_file(self, file_path: str) -> None:
        # inherit docstring from superclass
        while self._running and self._write_lock.acquire():
            try:
                super().write_file_via_unsecured(file_path)
            finally:
                self._write_lock.release()
                break

    def stop(self, disconnect: bool = False) -> None:
        # inherit docstring from superclass
        logger.debug('Stopping Xlink.')
        self._running = False
        while not self._open_channel_lock.acquire():
            time.sleep(0.1)
        logger.debug('Open channel lock get.')
        while not self._read_data_lock.acquire():
            time.sleep(0.01)
        logger.debug('read_data lock get.')
        time.sleep(1)
        logger.debug('Close Xlink channel ID - ' + str(self._channel_id.value))
        self._xlink_library.xlink_close_channel(byref(self._xlink_handler), self._channel_id)
        if disconnect:
            # Wait 0.5s to let xlink fully close the channel before disconnecting it.
            time.sleep(0.5)
            logger.debug('Disconnect Xlink')
            self._xlink_library.xlink_disconnect(byref(self._xlink_handler))
