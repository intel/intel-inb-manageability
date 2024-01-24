"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.detect_os import OsType

from .installer import *
from .rebooter import *
from .upgrade_checker import *
from ..packagemanager.irepo import IRepo

logger = logging.getLogger(__name__)


class OsFactory(ABC):
    """Abstract Factory for creating the concrete classes based on the OS
    on the platform.

    @param ota_element: ota element derived from the manifest
    """

    def __init__(self, ota_element: Dict) -> None:
        self._ota_element = ota_element

    @abstractmethod
    def create_upgrade_checker(self) -> UpgradeChecker: pass

    @abstractmethod
    def create_installer(self, repo: IRepo, fw_conf: str, fw_conf_schema: str) -> Installer:
        """This method creates and returns a OS specific installer for firmware update

        @param repo: repository to fetch the firmware file
        @param fw_conf: firmware config file path
        @param fw_conf_schema: firmware config schema location
        @return OS specific Installer
        """
        pass

    @abstractmethod
    def create_rebooter(self) -> Rebooter: pass

    @staticmethod
    def get_factory(os_type: str, ota_element: Any,  dispatcher_broker: DispatcherBroker) -> "OsFactory":
        logger.debug("")
        if os_type == OsType.Linux.name:
            return LinuxFactory(ota_element, dispatcher_broker)
        if os_type == OsType.Windows.name:
            return WindowsFactory(ota_element, dispatcher_broker)
        raise ValueError(f'Unsupported OS type: {os_type}.')


class LinuxFactory(OsFactory):
    """Abstract Factory for creating the concrete classes based on the OS
    on the platform.  This instance is for Linux.
    """

    def __init__(self, ota_element: Dict,  dispatcher_broker: DispatcherBroker) -> None:
        super().__init__(ota_element)
        self._dispatcher_broker = dispatcher_broker

    def create_upgrade_checker(self) -> UpgradeChecker:
        logger.debug(" ")
        return LinuxUpgradeChecker(self._ota_element, self._dispatcher_broker)

    def create_installer(self, repo: IRepo, fw_conf: str, fw_conf_schema: str) -> Installer:
        logger.debug(" ")
        return LinuxInstaller(self._dispatcher_broker, repo, fw_conf, fw_conf_schema)

    def create_rebooter(self) -> Rebooter:
        logger.debug(" ")
        return LinuxRebooter(self._dispatcher_broker)


class WindowsFactory(OsFactory):
    """Abstract Factory for creating the concrete classes based on the OS
    on the platform.  This instance is for Windows.
    """

    def __init__(self, ota_element: Dict,  dispatcher_broker: DispatcherBroker) -> None:
        super().__init__(ota_element)
        self._dispatcher_broker = dispatcher_broker

    def create_upgrade_checker(self) -> UpgradeChecker:
        logger.debug(" ")
        return WindowsUpgradeChecker(self._ota_element, self._dispatcher_broker)

    def create_installer(self, repo: IRepo, fw_conf: str, fw_conf_schema: str) -> Installer:
        logger.debug(" ")
        return WindowsInstaller(self._dispatcher_broker, repo, fw_conf, fw_conf_schema)

    def create_rebooter(self) -> Rebooter:
        logger.debug(" ")
        return WindowsRebooter(self._dispatcher_broker)
