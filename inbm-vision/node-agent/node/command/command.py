""""
    Class for creating Command object to be sent to the vision-agent and TC

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import platform
from enum import Enum
from typing import Optional, Tuple, List
from datetime import datetime, date
from abc import ABC, abstractmethod

from inbm_common_lib.utility import clean_input
from inbm_common_lib.dmi import get_dmi_system_info
from inbm_common_lib.device_tree import is_device_tree_exists, get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation

from node.constant import REQUEST_TO_DOWNLOAD_NAME, REGISTER_COMMAND_NAME, ARM, YOCTO, UBUNTU, AGENT, \
    SEND_DOWNLOAD_STATUS_NAME, CMDLINE_FILE_PATH, VERITY_DISABLED, VERITY_ENABLED, LOAD, APPEND, REMOVE, PROC_VERSION, \
    MEASURED_BOOT_PATH
from node.path_constant import STEPPING_PATH, SKU_PATH, MODEL_PATH, SERIAL_NUM_PATH

from ..space_calculator import get_free_space, get_free_memory
from ..broker import Broker
from ..node_exception import NodeException
from ..xlink_manager import XlinkManager
from ..mender_util import read_current_mender_version
from ..flashless_checker import is_flashless
from ..package_version import get_version

logger = logging.getLogger(__name__)


class NodeCommands(Enum):
    REQUEST_TO_DOWNLOAD = "requestToDownload"
    REGISTER_RESPONSE = "registerResponse"
    IS_ALIVE = "isAlive"
    OTA_UPDATE = "otaUpdate"
    get_configuration = "getConfigValues"
    set_configuration = "setConfigValues"
    append_configuration = "appendConfigValues"
    remove_configuration = "removeConfigValues"
    reregister = "reregister"
    config_request = "configRequest"
    RESTART = "restart"
    HEARTBEAT_RESPONSE = "heartbeatResponse"


class Command(ABC):
    """Basic command class for storing response and execute the function"""

    def __init__(self, nid: Optional[str]) -> None:
        self._nid = clean_input(nid) if nid else None

    @abstractmethod
    def execute(self):
        pass


class RequestToDownloadCommand(Command):
    """check system storage size to get the file download

       @param nid : Node Device ID
       @param xlink_manager : Node Xlink Manager
       @param download_size_kb: file size in kb
       @return : manifest with node id and storage checking status (True/False)
    """

    def __init__(self, nid, xlink_manager, download_size_kb):
        super(RequestToDownloadCommand, self).__init__(nid)
        self.name = REQUEST_TO_DOWNLOAD_NAME
        self.download_size_kb = download_size_kb
        self.xlink_manager = xlink_manager

    def execute(self) -> None:
        self.xlink_manager.send(self._is_enough_space(self.download_size_kb))

    def _is_enough_space(self, download_size_kb) -> str:
        # if it is flashless system, check free memory instead of storage
        free = get_free_memory() if is_flashless() else get_free_space()
        free_storage = free / 1024
        if free_storage > int(download_size_kb):
            logger.info(
                'Storage check passed. Available disk size: {}KB.'.format(free_storage))
            result = True
        else:
            logger.error('Less than {} KB free. Available disk size:{}KB'.format(
                download_size_kb, free_storage))
            result = False

        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<message>'
                    '    <sendFileResponse id="{}">'
                    '        <items>'
                    '            <sendDownload>{}</sendDownload>'
                    '        </items>'
                    '    </sendFileResponse>'
                    '</message>').format(self._nid, result)
        return manifest


class RegisterCommand(Command):
    """Create registry manifest to vision-agent for every system boot up

       @param xlink_manager : Node Xlink Manager
       @return : manifest with reg_id, os_version, os_type, bios_vendor, bios_version,
       bios_release_date, platform_mfg
    """

    def __init__(self, xlink_manager: Optional[XlinkManager]) -> None:
        super(RegisterCommand, self).__init__(None)
        self.name = REGISTER_COMMAND_NAME
        self.xlink_manager = xlink_manager

    def execute(self) -> None:
        reg_id = self._get_hddl_data()
        os_version, os_type, os_release_date = self._get_os_data()
        platform_info = self._get_fw_data()
        dm_verity_enabled = self._get_dm_verity_enable_status()
        version = get_version()
        if self.xlink_manager:
            is_xlink_secure = self.xlink_manager.is_xlink_secure()
        else:
            is_xlink_secure = False
        measured_boot_enabled = self._get_measured_boot_status()
        logger.info("DM_VERITY : {}".format(dm_verity_enabled))
        logger.info("MEASURED_BOOT : {}".format(measured_boot_enabled))
        text_boot_fw_date = str(platform_info.bios_release_date.month) + "-" + \
            str(platform_info.bios_release_date.day) + "-" + \
            str(platform_info.bios_release_date.year) \
            if isinstance(platform_info.bios_release_date, date) else "UNKNOWN"

        stepping, sku, model, serial_num = self._get_board_info()

        manifest = '<?xml version="1.0" encoding="utf-8"?>' + \
                   '<message>' + \
                   '    <register id="{}">'.format(reg_id) + \
                   '        <items>' + \
                   '            <bootFwDate>{}</bootFwDate>'.format(text_boot_fw_date) + \
                   '            <bootFwVendor>{}</bootFwVendor>'.format(platform_info.bios_vendor) + \
                   '            <bootFwVersion>{}</bootFwVersion>'.format(platform_info.bios_version) + \
                   '            <osType>{}</osType>'.format(os_type) + \
                   '            <osVersion>{}</osVersion>'.format(os_version) + \
                   '            <osReleaseDate>{}</osReleaseDate>'.format(os_release_date) + \
                   '            <manufacturer>{}</manufacturer>'.format(platform_info.platform_mfg) + \
                   '            <product>{}</product>'.format(platform_info.platform_product) + \
                   '            <dmVerityEnabled>{}</dmVerityEnabled>'.format(dm_verity_enabled)
        # suppress high Jones complexity warning:
        manifest += '            <measuredBootEnabled>{}</measuredBootEnabled>'.format(measured_boot_enabled) + \
                    '            <flashless>{}</flashless>'.format(is_flashless()) + \
                    '            <is_xlink_secure>{}</is_xlink_secure>'.format(is_xlink_secure) + \
                    '            <stepping>{}</stepping>'.format(stepping) + \
                    '            <sku>{}</sku>'.format(sku) + \
                    '            <model>{}</model>'.format(model) + \
                    '            <serialNumber>{}</serialNumber>'.format(serial_num) + \
                    '            <version>{}</version>'.format(version) + \
                    '        </items>' + \
                    '    </register>' + \
                    '</message>'

        if self.xlink_manager:
            self.xlink_manager.send(manifest)

    def _get_dm_verity_enable_status(self):
        with open(CMDLINE_FILE_PATH, 'r') as file:
            if VERITY_DISABLED in file.read():
                return False
            elif VERITY_ENABLED in file.read() and 'roothash' in file.read():
                return True

    def _get_measured_boot_status(self) -> str:
        try:
            with open(MEASURED_BOOT_PATH, 'r') as file:
                return file.read().split('\x00')[0]
        except (FileNotFoundError, OSError) as error:
            logger.error(f'Measured boot info not found due to: {error}')
        return "UNKNOWN"

    def _get_fw_data(self) -> PlatformInformation:
        """Get the FW information : Version , Release date , Vendor and platform_mfg"""
        return get_device_tree_system_info() if is_device_tree_exists() else get_dmi_system_info()

    def _get_hddl_data(self) -> str:
        """get the HDDL hardware id"""
        registry_id = "389C0A"
        if self.xlink_manager and self.xlink_manager.node_data_handler.get_nid():
            registry_id = self.xlink_manager.node_data_handler.get_nid()
        return registry_id

    # TODO (Nat): Use a dataclass instead of 3 returns
    def _get_os_data(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Gets the OS type and OS version"""
        platform_os = platform.system()
        logger.debug("Operating System:{}".format(os))

        if platform_os == 'Linux':
            v = platform.version()
            p = platform.platform()
            logger.debug("platform.platform():{}, platform.version():{}".format(p, v))

            if UBUNTU in v:
                # Set os_type to YOCTO if it is using xlink simulator. Used in integration test.
                os_type = YOCTO if 'XLINK_SIMULATOR' in os.environ and os.environ.get(
                    'XLINK_SIMULATOR') == 'True' else UBUNTU
                os_release_date = None  # TODO: check os release date in ubuntu
                u = v.split()[0]
                if "~" in u:
                    # #44~18.04.2-Ubuntu
                    os_version = u.split("~")[1].split("-")[0]
                else:
                    # #81-Ubuntu
                    os_version = v.split()[0].split("-")[0].replace('#', '')
            elif ARM in p:
                os_type = YOCTO
                os_version = v.split()[0].replace('#', '')
                try:
                    artifact_info = read_current_mender_version()
                    artifact_date_info = artifact_info.strip('Release-').strip()
                    artifact_datetime_info = datetime.strptime(artifact_date_info, "%Y%m%d%H%M%S")
                    month = str(artifact_datetime_info.month)
                    day = str(artifact_datetime_info.day)
                    year = str(artifact_datetime_info.year)
                    hour = str(artifact_datetime_info.hour)
                    minute = str(artifact_datetime_info.minute)
                    seconds = str(artifact_datetime_info.second)
                    os_release_date = "{0}-{1}-{2}-{3}-{4}-{5}".format(
                        month, day, year, hour, minute, seconds)
                except FileNotFoundError:
                    # No mender file in flashless device.
                    logger.error("Mender file not found.")
                    os_release_date = self._get_os_release_date_from_version_file()
            else:
                return None, None, None

            logger.debug("os_version:{} os_type:{} os_release_date:{}".format(
                os_version, os_type, os_release_date))

            return os_version, os_type, os_release_date
        else:
            return None, None, None

    def _get_os_release_date_from_version_file(self) -> Optional[str]:
        """get the release date from version file"""
        try:
            with open(PROC_VERSION, 'r') as version_file:
                # Example: 20201209083327
                content = version_file.read().rstrip()
                datetime_obj = datetime.strptime(content, "%Y%m%d%H%M%S")
                month = str(datetime_obj.month)
                day = str(datetime_obj.day)
                year = str(datetime_obj.year)
                hour = str(datetime_obj.hour)
                minute = str(datetime_obj.minute)
                seconds = str(datetime_obj.second)
                os_release_date = "{0}-{1}-{2}-{3}-{4}-{5}".format(
                    month, day, year, hour, minute, seconds)
                return os_release_date
        except (FileNotFoundError, ValueError) as error:
            # No mender file in flashless device.
            logger.error("Version file read error: {0}".format(error))
            return None

    def _get_board_info(self) -> Tuple[Optional[str], ...]:
        """get BKC version, SoC Type, Stepping and Board Type"""

        def _is_file_exist(os_path: str) -> bool:
            return True if os.path.exists(os_path) else False

        board_info: List[Optional[str]] = []
        for path in STEPPING_PATH, SKU_PATH, MODEL_PATH, SERIAL_NUM_PATH:
            if _is_file_exist(path):
                with open(path, "r") as read_file:
                    board_info.append(read_file.readline().rstrip('\n').split('\x00')[0])
            else:
                board_info.append(None)
        return tuple(board_info)


class SendHeartbeatCommand(Command):
    """Create heartbeat signal on every heartbeat interval or received "isalive" message from
    vision-agent

       @param nid : Node Device ID
       @param xlink_manager : Node Xlink Manager
       @return : manifest with nid info
    """

    def __init__(self, nid, xlink_manager):
        super(SendHeartbeatCommand, self).__init__(nid)
        self.xlink_manager = xlink_manager

    def execute(self) -> None:
        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<message>'
                    '    <heartbeat id="{}"/>'
                    '</message>').format(self._nid)

        self.xlink_manager.send(manifest)


class SendDownloadStatusCommand(Command):
    """Create file download status manifest

       @param nid : Node Device ID
       @param xlink_manager : Node Xlink Manager
       @param status : File download status

       @return : manifest with file download status (True|False)
    """

    def __init__(self, nid, xlink_manager, status):
        super(SendDownloadStatusCommand, self).__init__(nid)
        self.name = SEND_DOWNLOAD_STATUS_NAME
        self.status = status
        self.xlink_manager = xlink_manager

    def execute(self) -> None:
        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<message>'
                    '    <downloadStatus id="{}">'
                    '        <items>'
                    '            <status>{}</status>'
                    '        </items>'
                    '    </downloadStatus>'
                    '</message>').format(self._nid, self.status)

        self.xlink_manager.send(manifest)


class SendManifestCommand(Command):
    """Call broker to publish manifest

       @param nid : Node Device ID
       @param broker : Node broker
       @param manifest : manifest from vision-agent
    """

    def __init__(self, nid, broker, manifest):
        super(SendManifestCommand, self).__init__(nid)
        self.broker = broker
        self.manifest = manifest

    def execute(self) -> None:
        self.broker.push_ota(self.manifest)


class SendTelemetryEventCommand(Command):
    """SendTelemetryEventCommand Concrete class

    @param nid: id of node that sent response
    @param xlink_manager: Node Xlink Manager
    @param message: Telemetry event to send back to vision-agent via xlink
    """

    def __init__(self, nid: Optional[str], xlink_manager: Optional[XlinkManager], message: str) -> None:
        super(SendTelemetryEventCommand, self).__init__(nid)
        self.xlink_manager = xlink_manager
        self.message = message

    def execute(self) -> None:
        """Send telemetry event message through xlink"""
        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<message>'
                    '    <telemetryEvent id="{}">'
                    '        <items>'
                    '            <telemetryMessage>{}</telemetryMessage>'
                    '        </items>'
                    '    </telemetryEvent>'
                    '</message>').format(self._nid, self.message)
        if self.xlink_manager:
            self.xlink_manager.send(manifest)
        else:
            raise NodeException("Failed to send message via XLink")


class SendOtaResultCommand(Command):
    """SendOtaResultCommand Concrete class

    @param nid: id of node that sent response
    @param xlink_manager: Node Xlink Manager
    @param message: OTA result to send back to vision-agent via xlink
    """

    def __init__(self, nid: Optional[str], xlink_manager: Optional[XlinkManager], message: str) -> None:
        super(SendOtaResultCommand, self).__init__(nid)
        self.xlink_manager = xlink_manager
        self.message = message

    def execute(self) -> None:
        """Send telemetry event message through xlink"""
        manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                    '<message>'
                    '    <otaResult id="{}">'
                    '        <items>'
                    '            <result>{}</result>'
                    '        </items>'
                    '    </otaResult>'
                    '</message>').format(self._nid, self.message)
        if self.xlink_manager:
            self.xlink_manager.send(manifest)
        else:
            raise NodeException("Failed to send message via XLink")


class SendOtaClientConfigurationCommand(Command):
    """Call broker to publish manifest.

       @param broker : Node broker instance
       @param path : path
       @param config_type: configuration type: GET and SET
    """

    def __init__(self, broker: Optional[Broker], path: str, config_type: str) -> None:
        self.broker = broker
        self.config_type = config_type
        self.path = path

    def execute(self) -> None:
        if self.config_type != LOAD:
            if self.config_type == APPEND or self.config_type == REMOVE:
                cmd = self.config_type
            else:
                cmd = self.config_type + '_element'
            path = ""
            for num in self.path:
                path += num + ";"
            path = path[:-1]
        else:
            cmd = self.config_type
            path = self.path

        manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                    '<manifest>' +
                    '    <type>config</type>' +
                    '        <config>'
                    '            <cmd>{0}</cmd>' +
                    '                <configtype>' +
                    '                    <{1}>' +
                    '                        <path>{2}</path>' +
                    '                    </{1}>' +
                    '                </configtype>' +
                    '        </config>' +
                    '</manifest>').format(cmd, self.config_type, path)
        if self.broker:
            self.broker.push_ota(manifest)
