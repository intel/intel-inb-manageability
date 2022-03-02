"""
    XLinkManager manages the messages sent/received via xlink.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
from threading import Thread
from typing import Optional
from time import sleep
from inbm_vision_lib import checksum_validator
from inbm_vision_lib.xlink.xlink_wrapper import XlinkWrapper
from inbm_vision_lib.xlink.xlink_simulator_wrapper import XlinkSimulatorWrapper
from inbm_vision_lib.xlink.ixlink_wrapper import IXlinkWrapper, XlinkWrapperException, _is_xlink_secure_exist
from inbm_vision_lib.xlink.xlink_factory import xlink_wrapper_factory
from inbm_vision_lib.xlink.xlink_utility import get_all_xlink_pcie_device_ids
from inbm_vision_lib.constants import CACHE, UNSECURED_XLINK_CHANNEL, SECURED_XLINK_CHANNEL, \
    SECURE_XLINK_LIB_PATH, NODE
from .constant import REGISTRATION_RETRY_TIMER_SECS

logger = logging.getLogger(__name__)


class XlinkManager(object):
    """XLinkManager manages the messages sent/received via xlink.

    @param data_handler: Callback to DataHandler
    """

    def __init__(self, data_handler, config_callback):
        self.node_data_handler = data_handler
        self.xlink_pcie_num = 0
        self.xlink_retry_sec = int(config_callback.get_element(
            [REGISTRATION_RETRY_TIMER_SECS], NODE)[0])
        # Node agent will not use xlink boot device API.
        self._is_boot_device = False
        self._is_xlink_connected = False
        self.running = True
        self._is_secure_xlink = _is_xlink_secure_exist()
        self.xlink_wrapper: Optional[IXlinkWrapper] = None
        self.xlink_public_channel: Optional[IXlinkWrapper] = None
        if 'XLINK_SIMULATOR' in os.environ and os.environ.get('XLINK_SIMULATOR') == 'True':
            # In integration test, we use "389C0A" as node id
            self.node_data_handler._nid = "389C0A"
            self.xlink_wrapper = XlinkSimulatorWrapper(self.receive, UNSECURED_XLINK_CHANNEL)
            self.xlink_wrapper.start()
        else:
            self._start_public_thread()

    def _start_public_thread(self) -> None:
        """Start public channel for xlink connection"""
        public_channel_thread = Thread(target=self._query_channel)
        public_channel_thread.daemon = True
        public_channel_thread.start()

    def _query_channel(self) -> None:
        xlink_pcie_dev_list = get_all_xlink_pcie_device_ids(0)
        self.xlink_pcie_num = xlink_pcie_dev_list[0]

        self.xlink_public_channel = XlinkWrapper(
            self._receive_channel, UNSECURED_XLINK_CHANNEL, self.xlink_pcie_num, self._is_boot_device)
        while not self.xlink_public_channel.get_init_status() and self.running:
            sleep(1)

        self.xlink_public_channel.start()
        while self.running and not self._is_xlink_connected:
            try:
                self.xlink_public_channel.send(
                    "{0}/{1}".format(str(self._is_secure_xlink), self.xlink_pcie_num))
            except XlinkWrapperException as error:
                logger.error("{0}. Try again after {1} seconds".format(
                    error, str(self.xlink_retry_sec)))
            sleep(self.xlink_retry_sec)

    def _receive_channel(self, message: str) -> None:
        # Node receive channel id and node id. Example: 1282/01ff9982-1679820
        parsed_message = message.rsplit('/')
        channel_id = int(parsed_message[0])
        node_id = parsed_message[1]
        self.node_data_handler._nid = node_id

        self.xlink_wrapper = xlink_wrapper_factory(self._is_secure_xlink, self.receive, int(channel_id),
                                                   self.xlink_pcie_num, False, None)

        if self.xlink_public_channel:
            self.xlink_public_channel.stop(disconnect=True)
            self.xlink_public_channel = None

        self._is_xlink_connected = True

        while not self.xlink_wrapper.get_init_status() and self.running:
            pass

        if self.running and self.xlink_wrapper:
            self.xlink_wrapper.start()

        # if xlink connection is established, send the register request
        self.node_data_handler.register()

    def receive(self, message) -> None:
        """Callback while receiving message from xlink
        @param message: message received via xlink
        """
        logger.debug("XlinkManager: receive " + message)
        file_name = ""
        try:
            if message == "FILE":
                if self.xlink_wrapper:
                    file_name = self.xlink_wrapper.receive_file(CACHE)
                    self.node_data_handler.downloaded_file(file_name, True)
                else:
                    raise XlinkWrapperException(
                        "Xlink connection is not establish. Cannot receive file.")
            elif message == "RECONNECT":
                # When receive RECONNECT message, that means vision-agent is restarting/stopping.
                # Node will reset the heartbeat and all xlink connection. Prepare for reconnection.
                self.node_data_handler.reset_heartbeat()
                if self.xlink_wrapper:
                    self.xlink_wrapper.stop(disconnect=True)
                self._is_xlink_connected = False
                # Wait 1 minute for closing xlink on host system before reconnection
                logger.info(
                    "Detected vision-agent is restarting/stopping. Reconnecting in 60 seconds...")
                sleep(60)
                self._start_public_thread()
            else:
                self.node_data_handler.receive_xlink_message(message)
        except (OSError, XlinkWrapperException):
            self.node_data_handler.downloaded_file(file_name, False)

    def send(self, message):
        """Send the message through xlink
        @param message: String message to be sent
        """
        logger.debug("XlinkManager: send " + message)
        hash_value = checksum_validator.hash_message(message)
        message = message + "::" + hash_value
        try:
            if self.xlink_wrapper:
                self.xlink_wrapper.send(message)
            else:
                raise XlinkWrapperException(
                    "Xlink connection is not establish. Cannot send message.")
        except XlinkWrapperException as error:
            logger.error('Failed to send message through xlink : {}'.format(error))

    def get_init_status(self) -> bool:
        """ Get the initialization status.

        @return: boolean representing initialization status
        """
        if self.xlink_wrapper:
            return self.xlink_wrapper.get_init_status()
        else:
            # if xlink not connect and stop node agent, just return False
            return False

    def is_xlink_secure(self) -> bool:
        """ Determine whether secure xlink is used.

        @return: True if secure xlink is used. False if use regular xlink.
        """
        return self._is_secure_xlink

    def start(self) -> None:
        """Listen to xlink channel"""
        pass

    def stop(self) -> None:
        """Stop listening to xlink channel"""
        self.running = False
        if self.xlink_public_channel:
            self.xlink_public_channel.stop(disconnect=True)

        if self.xlink_wrapper:
            self.xlink_wrapper.send("DISCONNECT/{0}".format(self.node_data_handler.get_nid()))
            self.xlink_wrapper.stop(disconnect=True)

    def send_file(self, file_path: str) -> None:
        """Not used on the node"""
        pass

    def receive_file(self, file_save_path: str) -> str:
        """Not used on the node"""
        pass
