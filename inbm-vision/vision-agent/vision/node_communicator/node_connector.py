"""
    Highest level of abstraction for node communication.  Creates a concrete class for the method of communication
    to be used.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os

from typing import Any, List, Optional, Dict, Tuple

from inbm_vision_lib.configuration_manager import ConfigurationManager, ConfigurationException
from inbm_vision_lib.constants import XLINK_FIRST_CHANNEL, XLINK_LAST_CHANNEL, XLINK_BOOT_DEV_DEFAULT
from inbm_vision_lib.xlink.ixlink_wrapper import XlinkWrapperException
from inbm_common_lib.pms.pms_helper import PMSHelper, PmsException

from ..constant import AGENT
from ..configuration_constant import XLINK_PCIE_DEV_ID, XLINK_FIRST_CHANNEL_ID, XLINK_LAST_CHANNEL_ID, XLINK_BOOT_DEV
from ..data_handler.idata_handler import IDataHandler

from .ixlink_channel_connector import XlinkSimulatorConnector, IXlinkChannelConnector
from .xlink_connector import XlinkConnector

logger = logging.getLogger(__name__)


def _create_channel_connector_factory(data_handler: IDataHandler, channel_list: List[int],
                                      is_boot_device: bool) -> IXlinkChannelConnector:
    """Factory which creates the correct connector to nodes based on environment

    @param data_handler: DataHandler interface
    @param channel_list: list of channels to be used for communication
    @param is_boot_device: True if the device is a boot device; otherwise false.
    @return IXlinkChannelConnector concrete class
    """
    if 'XLINK_SIMULATOR' in os.environ and os.environ.get('XLINK_SIMULATOR') == 'True':
        return XlinkSimulatorConnector(data_handler, channel_list, is_boot_device)
    return XlinkConnector(data_handler, channel_list, is_boot_device)


class NodeConnector(object):
    """Class to receive/send message/file to nodes
    @param data_handler: DataHandler interface
    @param config_callback: ConfigurationManager object
    """

    def __init__(self, data_handler: IDataHandler, config_callback: ConfigurationManager) -> None:
        self._data_handler = data_handler
        self._xlink_pcie_num = int(config_callback.get_element([XLINK_PCIE_DEV_ID], AGENT)[0])
        self._config_callback = config_callback

        is_boot_device = self._get_config_value(XLINK_BOOT_DEV, XLINK_BOOT_DEV_DEFAULT)

        first_channel = self._get_config_value(XLINK_FIRST_CHANNEL_ID, XLINK_FIRST_CHANNEL)
        last_channel = self._get_config_value(XLINK_LAST_CHANNEL_ID, XLINK_LAST_CHANNEL)
        channel_list = list(range(first_channel, last_channel))

        self._channel_connector = _create_channel_connector_factory(
            self._data_handler, channel_list, is_boot_device)
        self._channel_connector.initialize()
        self.pms = PMSHelper()

    def _get_config_value(self, key: str, default_value) -> Any:
        try:
            if key == XLINK_BOOT_DEV:
                return self._config_callback.get_element([key], AGENT)[0] == 'true'
            else:
                return int(self._config_callback.get_element([key], AGENT)[0])
        except (AttributeError, ConfigurationException):
            logger.debug("Use default value for configuration key {}={}.".format(key, default_value))
            return default_value

    def send(self, message: str, node_id: str) -> None:
        """Sends message to specified node

        @param message: message to send
        @param node_id: node ID of the receiver.
        """
        logger.info("")
        try:
            self._channel_connector.send(message, node_id)
        except XlinkWrapperException as error:
            logger.error('Failed to send message via xlink : {}'.format(error))

    def send_file(self, node_id: str, file_path: str) -> None:
        """Send file to node

        @param node_id: node ID of the receiver
        @param file_path: location of file
        """
        logger.info(
            "XlinkManager: send update file to device %s. File location: %s", node_id, file_path)
        try:
            self._channel_connector.send_file(node_id, file_path)
        except XlinkWrapperException as error:
            logger.error('File failed to send through xlink : {}'.format(error))

    def stop(self) -> None:
        """Stops communication"""
        self._channel_connector.stop()

    def boot_device(self, node_id: str) -> None:
        """Boots the device

        @param node_id: ID of the device to boot
        """
        logger.info("Booting up device: {}".format(node_id))
        try:
            self._channel_connector.boot_device(node_id)
        except XlinkWrapperException as error:
            logger.error('Failed to boot up device {}: {}'.format(node_id, error))

    def reset_device(self, node_id: str) -> None:
        """Reset the device

        @param node_id: ID of the device to reset
        """
        logger.info("Resetting device: {}".format(node_id))
        try:
            self.pms.reset_device(node_id.split('-')[-1])
            logger.debug('Reset complete.')
        except PmsException as error:
            logger.error(f'Reset device via PMS failed with error: {error}')
            logger.debug('Switch to xlink reset.')
            try:
                self._channel_connector.reset_device(node_id)
            except XlinkWrapperException as error:
                logger.error('Failed to reset device {}: {}'.format(node_id, error))

    def check_platform_type(self, node_id: Optional[str], sw_device_id: Optional[str] = None) -> Optional[str]:
        """Check the platform type of node.

        @param node_id: ID of the device to be checked
        @param sw_device_id: sw_device_id of the device to be checked
        @return: the platform type. E.g. KMB
        """
        return self._channel_connector.get_platform_type(node_id, sw_device_id)

    def get_guid(self, sw_device_id: int) -> Tuple[str, str]:
        """Get node's GUID 

        @param sw_device_id: xlink sw device id
        @return: GUID of node, SVN of node
        """
        return self._channel_connector.get_guid(sw_device_id)

    def get_all_guid(self) -> List[Dict[str, bool]]:
        """Get all nodes' GUID and provisioned status from secure xlink library

        @return: List of node's GUID and its provisioned status
        """
        return self._channel_connector.get_all_guid()

    def is_provisioned(self, sw_device_id: int) -> bool:
        """Get node's provisioned status from secure xlink library

        @param sw_device_id: xlink sw device id
        @return: True if provisioned; otherwise False
        """
        return self._channel_connector.is_provisioned(sw_device_id)
