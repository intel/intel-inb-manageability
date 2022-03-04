"""
    Different command object will be created according to different request.
    Each concrete classes have different execute method for different purpose.

    @copyright: Copyright 2021 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""


from abc import ABC, abstractmethod
import logging
import re
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, Optional
from threading import Lock
from time import sleep
from ..constant import VisionException, FLASHLESS_TOOL_PATH
from ..registry_manager import RegistryManager

from ..broker import Broker

from inbm_common_lib.utility import clean_input

from inbm_vision_lib.constants import UNKNOWN, create_error_message, create_success_message, TBH
from inbm_vision_lib.shell_runner import PseudoShellRunner

from ..node_communicator.node_connector import NodeConnector

logger = logging.getLogger(__name__)


class VisionCommands(Enum):
    REGISTER = "register"
    HEARTBEAT = "heartbeat"
    DOWNLOAD_STATUS = "downloadStatus"
    SEND_FILE_RESPONSE = "sendFileResponse"
    OTA_RESULT = "otaResult"
    TELEMETRY_EVENT = "telemetryEvent"
    CONFIG_RESPONSE = "configResponse"


class OsType(Enum):
    YOCTO = auto()
    UBUNTU = auto()


class Command(ABC):

    """Abstract class for creating the Command classes
    @param nid: node ID
    """

    def __init__(self, nid: str) -> None:
        self._nid = clean_input(nid)

    @abstractmethod
    def execute(self):
        pass


class SendXlinkMessageCommand(Command):

    """SendXlinkMessageCommand Concrete class
    @param nid: ID of node.  not used.
    @param node_connector: connection to Xlink
    @param message: message to send via xlink
    """

    def __init__(self, nid: str, node_connector: Optional[NodeConnector], message: str) -> None:
        super().__init__(nid)
        self.node_connector = node_connector
        self.message = message

    def execute(self) -> None:
        """Call NodeConnector API to send message to node"""
        logger.debug('Execute SendXlinkMessageCommand.')
        if self.node_connector:
            self.node_connector.send(self.message, self._nid)


class UpdateNodeHeartbeatCommand(Command):

    """UpdateNodeHeartbeatCommand Concrete class
    @param nid: ID of node
    @param registry_manager: Registry manager instance
    """

    def __init__(self, nid: str, registry_manager: RegistryManager) -> None:
        super().__init__(nid)
        self.registry_manager = registry_manager

    def execute(self) -> None:
        """Call RegistryManager API to update node's heartbeat timestamp"""
        logger.debug('Execute UpdateNodeHeartbeatCommand.')
        self.registry_manager.update_heartbeat_timestamp(self._nid)


class RegisterNodeCommand(Command):

    """RegisterNodeCommand Concrete class
    @param nid: ID of node
    @param registry_manager: Registry manager instance
    @param node_info: Node information
    """

    def __init__(self, nid: str, registry_manager, node_info: Dict[str, Any]) -> None:
        super().__init__(nid)
        self.registry_manager = registry_manager
        self.node_info = node_info

    def _validate_info(self) -> None:
        """Validate information received from node

        @return: boolean
        """
        self._validate_vendor()
        self._validate_version()
        self._validate_os_version()
        self._validate_manufacturer()
        self._validate_boot_fw_date()
        self._validate_os_type()
        self._validate_dm_verity_enabled()
        self._validate_measured_boot_enabled()

    def _validate_boot_fw_date(self) -> None:
        """Validate date format received from node

        @return: boolean
        """
        datetime_format = '%Y-%m-%d %H:%M:%S'
        try:
            datetime.strptime(str(self.node_info["bootFwDate"]), datetime_format)
        except ValueError:
            raise VisionException("Date format check fail. Format should be YYYY-MM-DD HH:MM:SS")

    def _validate_vendor(self) -> None:
        """Validate vendor information. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["bootFwVendor"].strip():
            logger.debug('No boot vendor found.')
            self.node_info["bootFwVendor"] = UNKNOWN

    def _validate_version(self) -> None:
        """Validate version information. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["bootFwVersion"].strip():
            logger.debug('No boot version found.')
            self.node_info["bootFwVersion"] = UNKNOWN

    def _validate_os_type(self) -> None:
        """Validate os version. If it is empty or unsupported OS, return False.

        @raises VisionException - No OS or unsupported OS
        """
        if not self.node_info["osType"].strip():
            logger.debug('No OS type found.')
            self.node_info["osType"] = UNKNOWN
            raise VisionException("No OS type found.")

        support_flag = 0
        for os_supported in OsType:
            if re.search(os_supported.name, self.node_info["osType"], re.IGNORECASE):
                support_flag = 1
        if support_flag:
            logger.debug('OS supported.')
        else:
            raise VisionException("OS unsupported.")

    def _validate_os_version(self) -> None:
        """Validate os type. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["osVersion"].strip():
            logger.debug('No OS version found.')
            self.node_info["osVersion"] = UNKNOWN

    def _validate_manufacturer(self) -> None:
        """Validate manufacturer. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["manufacturer"].strip():
            logger.debug('No manufacturer found.')
            self.node_info["manufacturer"] = UNKNOWN

    def _validate_dm_verity_enabled(self) -> None:
        """Validate dm_verity_enabled status. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["dmVerityEnabled"]:
            logger.debug('Unable to identify DM_Verity. No dm_verity parameter found on system.')
            self.node_info["dmVerityEnabled"] = UNKNOWN

    def _validate_measured_boot_enabled(self) -> None:
        """Validate measured boot status. If it is empty, replaced it with UNKNOWN."""
        if not self.node_info["measuredBootEnabled"].strip():
            logger.debug(
                'Unable to determine Measured Boot status. No Measured Boot parameter found on system')
            self.node_info["measuredBootEnabled"] = UNKNOWN

    def execute(self) -> None:
        """Create Registry object with information provided by node and register it to list"""
        try:
            self._validate_info()
            self.registry_manager.add(self.node_info, self._nid)
        except VisionException as e:
            msg = "Node information format error: " + str(e)
            logger.error(msg)


class SendRestartNodeCommand(Command):
    """SendRestartNodeCommand Concrete class

        @param nid: id of node that sent response
        @param node_connector: instance of NodeConnector
        """

    def __init__(self, nid: str, node_connector: Optional[NodeConnector]) -> None:
        super().__init__(nid)
        self.node_connector = node_connector

    def execute(self) -> None:
        """Send revised OTA manifest to node through xlink manager"""
        logger.debug('Execute SendRestartNodeCommand.')
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '<message>'
                            '    <restart id="{0}">'
                            '        <items>'
                            '            <manifest>'
                            '                <type>cmd</type>'
                            '                <cmd>restart</cmd>'
                            '            </manifest>'
                            '        </items>'
                            '    </restart>'
                            '</message>'
                            ).format(self._nid)
        if self.node_connector:
            self.node_connector.send(revised_manifest, self._nid)


class ResetDeviceCommand(Command):
    """ResetDeviceCommand Concrete class

    @param nid: id of the node
    @param node_connector: instance of NodeConnector
    """

    def __init__(self, nid: str, node_connector: Optional[NodeConnector]) -> None:
        super().__init__(nid)
        self.node_connector = node_connector

    def execute(self) -> None:
        """Call node connector API to reboot the device"""
        logger.debug('Execute ResetDeviceCommand')

        if self.node_connector:
            if self.node_connector.check_platform_type(self._nid) == TBH:
                (output, err, code) = PseudoShellRunner.run(FLASHLESS_TOOL_PATH + " None unbind")
                if code == 0:
                    logger.debug("Unbind ep success.")
                else:
                    logger.debug("Unbind ep failed.")
            self.node_connector.reset_device(self._nid)
