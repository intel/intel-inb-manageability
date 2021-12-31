"""
    Concrete class for Xlink Communication

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from threading import Thread, Lock
from typing import Optional, List, Any, Callable, Dict, Tuple
from time import sleep
from ctypes import *

from inbm_vision_lib.constants import UNSECURED_XLINK_CHANNEL, XLINK_DEV_READY, XLINK_UNAVAILABLE, KMB
from inbm_vision_lib.xlink.xlink_utility import get_all_xlink_pcie_device_ids, filter_first_slice_from_list
from inbm_vision_lib.xlink.ixlink_wrapper import XlinkWrapperException, _is_xlink_secure_exist, X_LINK_SUCCESS
from inbm_vision_lib.xlink.xlink_factory import xlink_wrapper_factory
from inbm_vision_lib.xlink.xlink_secure_wrapper import XlinkSecureWrapper
from inbm_vision_lib.request_message_constants import NO_DEVICE_FOUND
from inbm_vision_lib.path_prefixes import IS_WINDOWS

from ..data_handler.idata_handler import IDataHandler
from ..constant import XLINK_STATUS_CHECKING_INTERVAL, VISION_ID, DEVICE_DOWN
from ..mac_address import get_mac_address

from .xlink import XlinkPublic, _xlink_factory
from .ixlink_channel_connector import IXlinkChannelConnector
from inbm_vision_lib.timer import Timer

logger = logging.getLogger(__name__)


class XlinkConnector(IXlinkChannelConnector):
    """Class to receive/send message/file through xlink

    @param data_handler: DataHandler object
    @param channel_list: List of private xlink channels
    @params is_boot_device: True if boot device; otherwise, false
    """

    def __init__(self, data_handler: IDataHandler, channel_list: List[int], is_boot_device: bool) -> None:
        super().__init__(data_handler, channel_list, is_boot_device)
        self._xlink_wrapper_public: List[XlinkPublic] = []
        self._running = True
        self.async_callback = self._create_async_callback_cfunction()
        self._query_channel_lock = Lock()

    def initialize(self) -> None:
        """Initializes Xlink communication"""
        public_channel_thread = Thread(target=self._start_public_channel)
        public_channel_thread.start()

    def send(self, message: str, node_id: str) -> None:
        """Sends message to specified node

        @param message: message to send
        @param node_id: node ID of the receiver.
        """
        hashed_message = self._create_hashed_message(message)
        for xlink in self._xlink_list:
            if xlink.node_id == node_id:
                xlink.xlink_wrapper.send(hashed_message)

    def receive(self, message: str) -> None:
        """Callback while receiving message from xlink
        TODO: confirm receive file flow
        Current flow:
        1. Vision-agent send message: 'FILE'
        2. Node receive message and know it will receive file
        3. Node switch to receive file mode
        4. Vision-agent send file name
        5. Node receive file name
        6. Vision-agent send update file
        7. Node receive update file
        @param message: string received from xlink
        """
        logger.info("XlinkManager: receive " + message)
        if "DISCONNECT" in message:
            # example: message = DISCONNECT/node_id
            node_id = message.rsplit("/")[-1]
            self._disconnect_channel(node_id)
        else:
            logger.debug("Message receive: {}".format(message))
            self._data_handler.receive_xlink_message(message)

    def send_file(self, node_id: str, file_path: str) -> None:
        """Send file to node

        @param node_id: string representing node's device id
        @param file_path: string representing location of file
        """
        if node_id:
            for x in self._xlink_list:
                if x.node_id == node_id:
                    x.xlink_wrapper.send_file(file_path)
        else:
            logger.error("Node id is not given.")

    def stop(self) -> None:
        """Stops Xlink communication"""
        self._running = False

        def create_thread_add_to_list(thread_list: List[Thread], method: Any) -> None:
            """Create and run the method with threading. Add the thread into thread list.

            @param thread_list: list of thread
            @param method: method to be executed
            """
            method_thread = Thread(target=method, args=(True,))
            method_thread.daemon = True
            method_thread.start()
            thread_list.append(method_thread)

        threads: List[Thread] = []
        if self._xlink_wrapper_public:
            for pb_channel in self._xlink_wrapper_public:
                create_thread_add_to_list(threads, pb_channel.xlink_wrapper.stop)

        if self._xlink_list:
            for xlink in self._xlink_list:
                xlink.xlink_wrapper.send("RECONNECT")
                create_thread_add_to_list(threads, xlink.xlink_wrapper.stop)

        # Check all xlink device are closed.
        while threads:
            for thread in threads:
                if not thread.is_alive():
                    threads.remove(thread)

    def boot_device(self, node_id: str) -> None:
        """Boots the device

        @param node_id: ID of the device to boot
        """
        if node_id:
            for xlink in self._xlink_list:
                if xlink.node_id == node_id:
                    xlink.xlink_wrapper.boot_device()
        else:
            logger.error("Node ID is not given.")

    def reset_device(self, node_id: str) -> None:
        """Reset the device

        @param node_id: ID of the device to reset
        """
        if node_id:
            if self.get_platform_type(node_id) == KMB:
                for pb_channel in self._xlink_wrapper_public:
                    if pb_channel.node_id == node_id:
                        pb_channel.xlink_wrapper.reset_device()

                for xlink in self._xlink_list:
                    if xlink.node_id == node_id:
                        xlink.xlink_wrapper.reset_device()
            else:
                logger.debug("Xlink reset only supported in KMB.")

    def _reconnect_public(self, node_xlink_dev_id: Optional[int], sw_dev_id: Optional[str] = None) -> None:
        """Close and reopen public channel"""
        logger.debug(f"node_xlink_dev_id = {node_xlink_dev_id}, sw_dev_id = {sw_dev_id}")
        if not node_xlink_dev_id and sw_dev_id:
            # This will be executed when OTA is completed on the node side.
            for xlink in self._xlink_list:
                logger.debug(f"Checking xlink.node_id =  {xlink.node_id}.")
                logger.debug(f"{xlink.node_id.split('-')[1]} ==  {sw_dev_id}")
                if xlink.node_id.split("-")[1] == str(sw_dev_id):
                    logger.debug(f"delete xlink from xlink list - {sw_dev_id}.")
                    xlink.xlink_wrapper.stop()
                    self._restore_channel(xlink.channel_id)
                    self._xlink_list.remove(xlink)

            for pb_channel in self._xlink_wrapper_public:
                if pb_channel.node_id:
                    if pb_channel.node_id.split("-")[1] == str(sw_dev_id):
                        pb_channel.xlink_wrapper.stop()
                        pb_channel.xlink_wrapper = xlink_wrapper_factory(False, self._receive_query,
                                                                         UNSECURED_XLINK_CHANNEL,
                                                                         pb_channel.xlink_pcie_dev_id,
                                                                         self._is_boot_device,
                                                                         None)
                        pb_channel.xlink_wrapper.start()

        elif self._xlink_wrapper_public:
            for pb_channel in self._xlink_wrapper_public:
                if pb_channel.xlink_pcie_dev_id == node_xlink_dev_id:
                    pb_channel.xlink_wrapper.stop(disconnect=True)
                    pb_channel.xlink_wrapper = xlink_wrapper_factory(False, self._receive_query,
                                                                     UNSECURED_XLINK_CHANNEL,
                                                                     node_xlink_dev_id, self._is_boot_device,
                                                                     None)
                    pb_channel.xlink_wrapper.start()

    def _disconnect_channel(self, node_id: str) -> None:
        """Disconnect xlink channel

        @param node_id: ID of node to disconnect xlink channel
        """
        for xlink in self._xlink_list:
            if xlink.node_id == node_id:
                xlink.xlink_wrapper.stop(disconnect=True)
                self._restore_channel(xlink.channel_id)
                self._xlink_list.remove(xlink)
        for pb_channel in self._xlink_wrapper_public:
            if pb_channel.node_id == node_id:
                pb_channel.xlink_wrapper.stop(disconnect=True)
                pb_channel.xlink_wrapper = xlink_wrapper_factory(False, self._receive_query,
                                                                 UNSECURED_XLINK_CHANNEL,
                                                                 pb_channel.xlink_pcie_dev_id,
                                                                 self._is_boot_device,
                                                                 None)
                pb_channel.xlink_wrapper.start()

    def _restore_channel(self, channel_id: int) -> None:
        """Add the channel to channel list"""
        self._channel_list.append(channel_id)

    def _start_public_channel(self) -> None:
        """Start the public channel"""
        while self._running:
            self.xlink_pcie_dev_list = get_all_xlink_pcie_device_ids(0) \
                if not IS_WINDOWS else get_all_xlink_pcie_device_ids(64)
            self.xlink_pcie_dev_list = filter_first_slice_from_list(self.xlink_pcie_dev_list)
            logger.debug(f"xlink dev to be connected = {self.xlink_pcie_dev_list}")
            if len(self.xlink_pcie_dev_list) > 0:
                break
            else:
                logger.error(NO_DEVICE_FOUND)
                # If no xlink device found/xlink driver not installed. Send message to inform INBC.
                self._data_handler.publish_xlink_status(VISION_ID, NO_DEVICE_FOUND)
            sleep(30)

        for dev in range(len(self.xlink_pcie_dev_list)):
            xlink_wrapper_public = xlink_wrapper_factory(False, self._receive_query, UNSECURED_XLINK_CHANNEL,
                                                         self.xlink_pcie_dev_list[dev], self._is_boot_device,
                                                         self.async_callback)
            xlink_public = XlinkPublic(
                xlink_wrapper_public, self.xlink_pcie_dev_list[dev], None)
            self._xlink_wrapper_public.append(xlink_public)
            xlink_wrapper_public.start()

        # Periodically checking public channel, if xlink device is down, close that xlink channel and reconnect again.
        if len(self.xlink_pcie_dev_list) > 0:
            check_public_channel_thread = Timer(
                XLINK_STATUS_CHECKING_INTERVAL, self._check_xlink_device_status)
            check_public_channel_thread.start()

    def _receive_query(self, message: str) -> None:
        """Send the private channel to node"""
        # First message from node is whether node use secure xlink
        # example: message = True/17104896
        parsed_message = message.rsplit('/')
        is_secure_xlink = parsed_message[0] == "True"
        node_xlink_dev_id = int(parsed_message[1])
        while self._running and self._query_channel_lock.acquire():
            try:
                new_channel_id = self._get_free_channel()
            finally:
                self._query_channel_lock.release()
                break
        self._add_xlink_wrapper(new_channel_id, is_secure_xlink, node_xlink_dev_id)
        self._reconnect_public(node_xlink_dev_id)

    def _add_xlink_wrapper(self, channel_id: int, is_secure_xlink: bool, node_xlink_dev_id: int):
        try:
            if is_secure_xlink and not _is_xlink_secure_exist():
                logger.error(
                    "Secure Xlink not found on host. Connection with node agent failed.")
                return

            is_secure = True if is_secure_xlink else False
            xlink_wrapper = xlink_wrapper_factory(is_secure, self.receive, channel_id,
                                                  node_xlink_dev_id, self._is_boot_device,
                                                  None)

            sleep(1)
            node_id = self._create_node_id(str(xlink_wrapper.get_device_id()))
            new_xlink = _xlink_factory(xlink_wrapper, is_secure, channel_id, node_id)
            self._xlink_list.append(new_xlink)
            # Send channel id to node
            if self._xlink_wrapper_public:
                for pb_channel in self._xlink_wrapper_public:
                    if pb_channel.xlink_pcie_dev_id == node_xlink_dev_id:
                        pb_channel.node_id = node_id
                        pb_channel.xlink_wrapper.send(
                            "{0}/{1}".format(str(channel_id), node_id))
            logger.debug("Created xlink connection to node {0}.  Secure: {1}".format(
                node_id, is_secure))
            # waiting for xlink initialization complete and start the listen thread
            while not xlink_wrapper.get_init_status() and self._running:
                sleep(0.1)
            xlink_wrapper.start()
        except XlinkWrapperException as error:
            # If the write operation timeout, re-connect the public channel for next round of connection.
            logger.error("{0}. Reconnect xlink channel after 5 seconds.".format(str(error)))
            sleep(5)
            self._reconnect_public(node_xlink_dev_id)

    def _check_xlink_device_status(self) -> None:
        """Used in a timer to periodically check xlink device status.  Creates a sub-thread to check the status of
        the device on the public channel.
        """
        for xlink_public_channel in self._xlink_wrapper_public:
            check_single_xlink_thread = Thread(
                target=self._check_single_xlink, args=(xlink_public_channel,))
            check_single_xlink_thread.daemon = True
            check_single_xlink_thread.start()

        if self._running:
            check_public_channel_thread = Timer(
                XLINK_STATUS_CHECKING_INTERVAL, self._check_xlink_device_status)
            check_public_channel_thread.start()

    def _check_single_xlink(self, xlink_public: XlinkPublic):
        """Check the status of single xlink device.
        If status is not XLINK_DEV_READY, disconnect all xlink channels for this xlink device and reconnect.

        @param xlink_public: xlink device to be checked
        """
        device_status = xlink_public.xlink_wrapper.get_xlink_device_status()
        if device_status != XLINK_DEV_READY and device_status != XLINK_UNAVAILABLE:
            logger.debug("Node {0} status is {1}.".format(
                xlink_public.node_id, device_status))

        # Publish device status to DEVICE_STATUS_CHANNEL. INBC listens to this channel.
        if xlink_public.node_id:
            self._data_handler.publish_xlink_status(xlink_public.node_id, str(device_status))

    @staticmethod
    def _create_node_id(sw_device_id: str) -> str:
        """Create node id with MAC addr and sw device id

        @return: node device id to be registered
        """
        host_mac_addr = get_mac_address()
        if not host_mac_addr:
            logger.info("No MAC address found. Use default vision id - {0}".format(VISION_ID))
            host_mac_addr = VISION_ID

        host_mac_addr = host_mac_addr.strip('\n')
        host_mac_addr = host_mac_addr.replace(':', '')  # Linux
        host_mac_addr = host_mac_addr.replace('-', '')  # Windows
        node_id = "{0}-{1}".format(host_mac_addr, sw_device_id)
        return node_id

    def _get_free_channel(self) -> int:
        """Get the available channel from the channel list."""
        channel_id = None
        if self._channel_list:
            channel_id = self._channel_list[0]
            self._channel_list.remove(channel_id)
        if channel_id is None:
            raise XlinkWrapperException("No channel ID.")
        return channel_id

    def get_platform_type(self, node_id: Optional[str], sw_device_id: Optional[str] = None) -> Optional[str]:
        """Check the platform type of device

        @param node_id: ID of the device to be checked
        @param sw_device_id: software device id of the device to be checked
        @return: platform type of node, e.g. TBH, KMB
        """
        # TODO:  (Nat) Raise instead of returning None
        # TODO:  (Nat) Platform type returned should be an enum instead of a string
        platform_type = None
        logger.debug(f"Checking platform type of node {node_id}.")

        if node_id or sw_device_id:
            for xlink in self._xlink_wrapper_public:
                if xlink.node_id == node_id:
                    return xlink.xlink_wrapper.get_platform_type()
                elif sw_device_id and xlink.node_id:
                    if xlink.node_id.split("-")[1] == sw_device_id:
                        return xlink.xlink_wrapper.get_platform_type()
            logger.error("No matching ID.")
        else:
            logger.error("ID was not given.")
        return platform_type

    def _xlink_async_callback(self, sw_device_id: int, event_type: int) -> int:
        """Register callback to get the notification of xlink device disconnect/reconnect from PCIe.

        @param sw_device_id: xlink sw device id
        @param event_type: 0 is device disconnect, 1 is device connected
        @return: xlink success status to xlink
        """
        logger.debug('SW Device ID = {0}, type={1}'.format(sw_device_id, type(sw_device_id)))
        logger.debug('Event type = {0}, type={1}'.format(event_type, type(event_type)))
        # Currently we just reconnect xlink device when the event happened.
        if str(event_type) == DEVICE_DOWN:
            self._data_handler.boot_device(str(sw_device_id))

        self._reconnect_public(None, str(sw_device_id))
        return X_LINK_SUCCESS

    def get_guid(self, sw_device_id: int) -> Tuple[str, str]:
        """Get node's GUID from secure xlink library

        @param sw_device_id: xlink sw device id
        @return: GUID of node, SVN of node
        """
        logger.debug(f"Checking GUID and SVN for device {sw_device_id}")
        guid = "0"
        svn = "0"
        for xlink in self._xlink_list:
            if xlink.node_id == str(sw_device_id):
                guid, svn = XlinkSecureWrapper.get_guid(sw_device_id)  # type: ignore
        return guid, svn

    def get_all_guid(self) -> List[Dict[str, bool]]:
        """Get node's GUID and svn from secure xlink library

        @return: nodes' GUID and its provisioned status
        """
        guid_svn = []
        all_xlink_dev_list = get_all_xlink_pcie_device_ids(0) \
            if not IS_WINDOWS else get_all_xlink_pcie_device_ids(64)
        xlink_first_slice_list = filter_first_slice_from_list(all_xlink_dev_list)
        for xlink in xlink_first_slice_list:
            try:
                guid, svn = XlinkSecureWrapper.get_guid(xlink)  # type: ignore
                result = {f"{guid}_{svn}": XlinkSecureWrapper.is_provisioned(xlink)}
                guid_svn.append(result)
            except AttributeError as error:
                logger.debug(f"Unable to get GUID and SVN due to {error}")
        return guid_svn

    def is_provisioned(self, sw_device_id: int) -> bool:
        """Get node's provisioned status from secure xlink library

        @param sw_device_id: xlink sw device id
        @return: True if provisioned; False if not provisioned
        """
        logger.debug(f"Checking provisioned status for device {sw_device_id}")
        status = False
        for xlink in self._xlink_list:
            if xlink.node_id == str(sw_device_id):
                status = XlinkSecureWrapper.is_provisioned(
                    sw_device_id)  # type: ignore
        return status

    def _create_async_callback_cfunction(self) -> Callable:
        """Create ctypes pointer to python xlink async callback

        @return: pointer to callback
        """
        ctypes_callback_function = CFUNCTYPE(c_int, c_uint32, c_uint32)
        async_callback_p = ctypes_callback_function(self._xlink_async_callback)
        cast(async_callback_p, POINTER(c_int))
        return async_callback_p
