"""
    Interface for Xlink communication.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from typing import List, Tuple, Dict, Optional
from abc import ABC, abstractmethod

from inbm_vision_lib.xlink.xlink_simulator_wrapper import XlinkSimulatorWrapper
from inbm_vision_lib.constants import UNSECURED_XLINK_CHANNEL
from inbm_vision_lib import checksum_validator

from ..data_handler.idata_handler import IDataHandler

from .xlink import IXlink

logger = logging.getLogger(__name__)


class IXlinkChannelConnector(ABC):
    """Interface for Xlink communication

    @param data_handler: DataHandler object
    @param channel_list: List of private xlink channels
    @param is_boot_device: True if boot device; otherwise, false
    """

    def __init__(self, data_handler: IDataHandler, channel_list: List[int], is_boot_device: bool) -> None:
        self._data_handler = data_handler
        self._channel_list = channel_list
        self._is_boot_device = is_boot_device
        self.pcie_dev_list: List[int] = []
        self._xlink_list: List[IXlink] = []
        self.running = True

    @abstractmethod
    def stop(self) -> None:
        """Stops Xlink communication"""
        self.running = False

    @abstractmethod
    def initialize(self) -> None:
        """Initializes Xlink communication"""
        pass

    @abstractmethod
    def receive(self, message: str) -> None:
        """Receive message from node

        @param message: Message received.
        """
        pass

    @abstractmethod
    def send(self, message: str, node_id: str) -> None:
        """Sends message to specified node

        @param message: message to send
        @param node_id: node ID of the receiver.
        """
        pass

    @abstractmethod
    def send_file(self, node_id: str, file_path: str) -> None:
        """Send file to node

        @param node_id: node ID of the receiver
        @param file_path: location of file
        """
        pass

    @abstractmethod
    def boot_device(self, node_id: str) -> None:
        """Boots the device

        @param node_id: ID of the device to boot
        """
        pass

    @abstractmethod
    def reset_device(self, node_id: str) -> None:
        """Reset the device

        @param node_id: ID of the device to reset
        """
        pass

    @abstractmethod
    def get_guid(self, sw_device_id: int) -> Tuple[str, str]:
        """Get node's GUID 

        @param sw_device_id: xlink sw device id
        @return: GUID of node, SVN of node
        """
        pass

    @abstractmethod
    def get_all_guid(self) -> List[Dict[str, bool]]:
        """Get node's GUID and svn from secure xlink library

        @return: nodes' GUID and its provisioned status
        """
        pass

    @abstractmethod
    def is_provisioned(self, sw_device_id: int) -> bool:
        """Get node's provisioned status from secure xlink library

        @param sw_device_id: xlink sw device id
        @return: True if provisioned; otherwise False
        """
        pass

    @abstractmethod
    def get_platform_type(self, node_id: Optional[str], sw_device_id: Optional[str] = None) -> Optional[str]:
        """Check the platform type of device

        @param node_id: ID of the device to be checked
        @param sw_device_id: software device id of the device to be checked
        @return: platform type of node, e.g. TBH, KMB
        """
        pass

    @staticmethod
    def _create_hashed_message(message: str):
        logger.info("XlinkConnector: send " + message)
        hash_value = checksum_validator.hash_message(message)
        return message + "::" + hash_value


class XlinkSimulatorConnector(IXlinkChannelConnector):
    """Class to receive/send message/file through xlink simulator

    @param data_handler: DataHandler object
    @param channel_list: List of private xlink channels
    @param is_boot_device: True if boot device; otherwise, false
    """

    def __init__(self, data_handler: IDataHandler, channel_list: List[int], is_boot_device: bool) -> None:
        super().__init__(data_handler, channel_list, is_boot_device)
        self.xlink_simulator_wrapper = XlinkSimulatorWrapper(
            self.receive, UNSECURED_XLINK_CHANNEL)

    def initialize(self) -> None:
        """Initializes Xlink communication"""
        self.xlink_simulator_wrapper.start()

    def receive(self, message: str) -> None:
        """Callback while receiving message from xlink"

        @param message: message received
        """
        logger.debug("Message receive: {}".format(message))
        self._data_handler.receive_xlink_message(message)

    def send(self, message: str, node_id: str) -> None:  # type: ignore
        """Send message to node

        @param message: message to be sent
        @param node_id: id of node to send message to
        """
        hashed_message = self._create_hashed_message(message)
        self.xlink_simulator_wrapper.send(hashed_message)

    def send_file(self, node_id: str, file_path: str) -> None:
        """Send file to node

        @param node_id: string representing node's device id
        @param file_path: string representing location of file
        """
        if self.xlink_simulator_wrapper:
            self.xlink_simulator_wrapper.send_file(file_path)

    def stop(self) -> None:
        """Stops Xlink communication"""
        pass

    def boot_device(self, node_id: str) -> None:
        """Boots the device

        @param node_id: ID of the device to boot
        """
        if self.xlink_simulator_wrapper:
            self.xlink_simulator_wrapper.boot_device()

    def reset_device(self, node_id: str) -> None:
        """Resets the device

        @param node_id: ID of the device to reset
        """
        if self.xlink_simulator_wrapper:
            self.xlink_simulator_wrapper.reset_device()

    def get_guid(self, sw_device_id: int) -> Tuple[str, str]:
        """Get node's GUID 

        @param sw_device_id: xlink sw device id
        @return: GUID of node, SVN of node
        """
        return "0", "0"

    def get_all_guid(self) -> List[Dict[str, bool]]:
        """Get node's GUID and svn from secure xlink library

        @return: nodes' GUID and its provisioned status
        """
        return []

    def is_provisioned(self, sw_device_id: int) -> bool:
        """Get node's provisioned status from secure xlink library

        @param sw_device_id: xlink sw device id
        @return: True if provisioned; otherwise False
        """
        return True

    def get_platform_type(self, node_id: Optional[str], sw_device_id: Optional[str] = None) -> Optional[str]:
        """Check the platform type of device

        @param node_id: ID of the device to be checked
        @param sw_device_id: software device id of the device to be checked
        @return: platform type of node, e.g. TBH, KMB
        """
        return None
