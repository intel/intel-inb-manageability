"""
    SOTA updates factory class. Used to trigger
    package installation, updates, security updates etc
    
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
from abc import ABC, abstractmethod
from enum import Enum

from inbm_lib.detect_os import OsType, LinuxDistType

from .constants import BTRFS
from .downloader import *
from .os_updater import DebianBasedUpdater, WindowsUpdater, YoctoX86_64Updater, OsUpdater, YoctoARMUpdater, \
    TiberOSUpdater
from .rebooter import *
from .setup_helper import *
from .setup_helper import SetupHelper
from .snapshot import *

logger = logging.getLogger(__name__)



class SotaOsFactory:
    """Creates instances of OsFactory based on detected platform
    """

    def __init__(self,  dispatcher_broker: DispatcherBroker,
                 sota_repos: Optional[str] = None, package_list: list[str] = [],
                 signature: Optional[str] = None) -> None:
        """Initializes OsFactory.

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param sota_repos: new Ubuntu/Debian mirror (or None)
        @param package_list: list of packages to install/update (or empty for all--general upgrade)
        @param signature: signature used to verify image
        """
        self._sota_repos = sota_repos
        self._package_list = package_list
        self._dispatcher_broker = dispatcher_broker
        self._signature = signature

    @staticmethod
    def verify_os_supported() -> str:
        logger.debug("")
        os_type = platform.system()
        if os_type in OsType.__members__:
            return os_type
        else:
            raise ValueError('Unsupported OS type.')

    def get_os(self, os_type) -> "ISotaOs":
        """Gets the concrete OS-based class for the current operating system

        @return concrete class for the operating system
        """
        if os_type == LinuxDistType.Ubuntu.name:
            logger.debug("Ubuntu returned")
            return DebianBasedSotaOs(self._dispatcher_broker, self._sota_repos, self._package_list)
        elif os_type == LinuxDistType.Deby.name:
            logger.debug("Deby returned")
            return DebianBasedSotaOs(self._dispatcher_broker, self._sota_repos, self._package_list)
        elif os_type == LinuxDistType.Debian.name:
            logger.debug("Debian returned")
            return DebianBasedSotaOs(self._dispatcher_broker, self._sota_repos, self._package_list)
        elif os_type == LinuxDistType.YoctoX86_64.name:
            logger.debug("YoctoX86_64 returned")
            return YoctoX86_64(self._dispatcher_broker)
        elif os_type == LinuxDistType.YoctoARM.name:
            logger.debug("YoctoARM returned")
            return YoctoARM(self._dispatcher_broker)
        elif os_type == OsType.Windows.name:
            logger.debug("Windows returned")
            return Windows(self._dispatcher_broker)
        #TODO: Remove this when confirmed that TiberOS is in use
        elif os_type == LinuxDistType.Mariner.name:
            logger.debug("Mariner returned")
            return TiberOSBasedSotaOs(self._dispatcher_broker, self._signature)
        elif os_type == LinuxDistType.TiberOS.name:
            logger.debug("TiberOS returned")
            return TiberOSBasedSotaOs(self._dispatcher_broker, self._signature)
        raise ValueError('Unsupported OS type: ' + os_type)


class ISotaOs(ABC):
    """Represents an operating system. Produces concrete classes to perform actions based on the Os."""
    @abstractmethod
    def create_setup_helper(self) -> SetupHelper:
        pass

    @abstractmethod
    def create_rebooter(self) -> Rebooter:
        """Create a Rebooter object with a reboot() method for the current system."""
        pass

    @abstractmethod
    def create_os_updater(self) -> OsUpdater:
        """Create an updater object"""
        pass

    @abstractmethod
    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        """Create a snapshotter object

        @param sota_cmd: Command to create a snapshot
        @param snap_num: Snapshot number
        @param proceed_without_rollback: True to not rollback the system in event of an error;
        False to rollback.
        @param reboot_device: If True, reboot device on success or failure, otherwise, do not reboot.
        """
        pass

    @abstractmethod
    def create_downloader(self) -> Downloader:
        """Create a downloader object"""
        pass


class YoctoX86_64(ISotaOs):
    """YoctoX86_64 class, child of ISotaOs"""

    def __init__(self,  dispatcher_broker: DispatcherBroker) -> None:
        """Constructor.

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        """
        self._dispatcher_broker = dispatcher_broker

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return YoctoSetupHelper(self._dispatcher_broker)

    def create_rebooter(self) -> Rebooter:
        logger.debug("")
        return LinuxRebooter(self._dispatcher_broker)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return YoctoX86_64Updater()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return YoctoSnapshot(trtl, sota_cmd, self._dispatcher_broker, snap_num,
                             proceed_without_rollback, reboot_device)

    def create_downloader(self) -> Downloader:
        """ Create a downloader object"""
        logger.debug("")
        return YoctoDownloader()


class YoctoARM(ISotaOs):
    """YoctoARM class, child of ISotaOs"""

    def __init__(self,  dispatcher_broker: DispatcherBroker) -> None:
        self._dispatcher_broker = dispatcher_broker

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return YoctoSetupHelper(self._dispatcher_broker)

    def create_rebooter(self) -> Rebooter:
        logger.debug("")
        return LinuxRebooter(self._dispatcher_broker)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return YoctoARMUpdater()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return YoctoSnapshot(trtl, sota_cmd, self._dispatcher_broker,
                             snap_num, proceed_without_rollback, reboot_device)

    def create_downloader(self) -> Downloader:
        """ Create a downloader object"""
        logger.debug("")
        return YoctoDownloader()


class DebianBasedSotaOs(ISotaOs):
    """DebianBasedSotaOs class, child of ISotaOs"""

    def __init__(self,
                 dispatcher_broker: DispatcherBroker,
                 sota_repos: Optional[str],
                 package_list: list[str]) -> None:
        """Constructor.

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param sota_repos: new Ubuntu/Debian mirror (or None)
        @param package_list: list of packages to install/update (empty list for all/general upgrade)
        """
        self._sota_repos = sota_repos
        self._package_list = package_list
        self._dispatcher_broker = dispatcher_broker

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return DebianBasedSetupHelper(self._sota_repos)

    def create_rebooter(self) -> Rebooter:
        return LinuxRebooter(self._dispatcher_broker)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return DebianBasedUpdater(self._package_list)

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return DebianBasedSnapshot(trtl, sota_cmd, self._dispatcher_broker,
                                   snap_num, proceed_without_rollback, reboot_device)

    def create_downloader(self) -> Downloader:
        """ Create a downloader object"""
        return DebianBasedDownloader()


class Windows(ISotaOs):
    """Windows class, child of ISotaOs"""

    def __init__(self, dispatcher_broker: DispatcherBroker) -> None:
        """Constructor.

        """
        self._dispatcher_broker = dispatcher_broker

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return WindowsSetupHelper()

    def create_rebooter(self) -> Rebooter:
        return WindowsRebooter(self._dispatcher_broker)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return WindowsUpdater()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner())
        return WindowsSnapshot(trtl, sota_cmd, snap_num,
                               proceed_without_rollback, reboot_device)

    def create_downloader(self) -> Downloader:
        """ Create a downloader object"""
        return WindowsDownloader()


class TiberOSBasedSotaOs(ISotaOs):
    """TiberOSBasedSotaOs class, child of ISotaOs"""

    def __init__(self,  dispatcher_broker: DispatcherBroker, signature: Optional[str] = None) -> None:
        """Constructor.

        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param signature: signature used to verify image
        """
        self._dispatcher_broker = dispatcher_broker
        self._signature = signature

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return TiberOSSetupHelper(self._dispatcher_broker)

    def create_rebooter(self) -> Rebooter:
        logger.debug("")
        return LinuxRebooter(self._dispatcher_broker)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return TiberOSUpdater(signature=self._signature)

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str],
                           proceed_without_rollback: bool, reboot_device: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return TiberOSSnapshot(trtl, sota_cmd, self._dispatcher_broker, snap_num,
                             proceed_without_rollback, reboot_device)

    def create_downloader(self) -> Downloader:
        """ Create a downloader object"""
        logger.debug("")
        return TiberOSDownloader()
