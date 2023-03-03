"""
    SOTA updates factory class. Used to trigger
    package installation, updates, security updates etc
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
from abc import ABC, abstractmethod
from enum import Enum

from inbm_lib.detect_os import OsType

from .constants import BTRFS
from .downloader import *
from .os_updater import DebianBasedUpdater, WindowsUpdater, YoctoX86_64Updater, OsUpdater, YoctoARMUpdater
from .os_upgrader import OsUpgrader, UbuntuUpgrader, WindowsUpgrader, YoctoUpgrader
from .rebooter import *
from .setup_helper import *
from .setup_helper import SetupHelper
from .snapshot import *

logger = logging.getLogger(__name__)


class LinuxDistType(Enum):
    """Supported Linux Distributions"""
    Ubuntu = 0
    YoctoX86_64 = 1
    YoctoARM = 2
    Deby = 3
    Debian = 4


class SotaOsFactory:
    """Creates instances of OsFactory based on detected platform
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        """Initializes OsFactory.

        @param dispatcher_callbacks: DispatcherCallbacks
        """
        self._dispatcher_callbacks = dispatcher_callbacks

    @staticmethod
    def verify_os_supported() -> str:
        logger.debug("")
        os_type = platform.system()
        if os_type in OsType.__members__:
            return os_type
        else:
            raise ValueError('Unsupported OS type.')

    def get_os(self, os_type) -> "ISotaOs":
        """Gets the concrete Os-based class for the current operating system

        @return concrete class for the operating system
        """
        if os_type == LinuxDistType.Ubuntu.name:
            logger.debug("Ubuntu returned")
            return DebianBasedSotaOs(self._dispatcher_callbacks)
        elif os_type == LinuxDistType.Deby.name:
            logger.debug("Deby returned")
            return DebianBasedSotaOs(self._dispatcher_callbacks)
        elif os_type == LinuxDistType.Debian.name:
            logger.debug("Debian returned")
            return DebianBasedSotaOs(self._dispatcher_callbacks)
        elif os_type == LinuxDistType.YoctoX86_64.name:
            logger.debug("YoctoX86_64 returned")
            return YoctoX86_64(self._dispatcher_callbacks)
        elif os_type == LinuxDistType.YoctoARM.name:
            logger.debug("YoctoARM returned")
            return YoctoARM(self._dispatcher_callbacks)
        elif os_type == OsType.Windows.name:
            logger.debug("Windows returned")
            return Windows(self._dispatcher_callbacks)
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
    def create_os_upgrader(self) -> OsUpgrader:
        """Create an upgrader object"""
        pass

    @abstractmethod
    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str], proceed_without_rollback: bool) -> Snapshot:
        """Create a snapshotter object

        @param sota_cmd: Command to create a snapshot
        @param snap_num: Snapshot number
        @param proceed_without_rollback: True to not rollback the system in event of an error;
        False to rollback.
        """
        pass

    @abstractmethod
    def create_downloader(self) -> Downloader:
        """Create a downloader object"""
        pass


class YoctoX86_64(ISotaOs):
    """YoctoX86_64 class, child of ISotaOs"""

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        """Constructor.

        @param dispatcher_callbacks: DispatcherCallbacks instance
        """
        self._dispatcher_callbacks = dispatcher_callbacks

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return YoctoSetupHelper(self._dispatcher_callbacks)

    def create_rebooter(self) -> Rebooter:
        logger.debug("")
        return LinuxRebooter(self._dispatcher_callbacks)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return YoctoX86_64Updater()

    def create_os_upgrader(self) -> OsUpgrader:
        logger.debug("")
        return YoctoUpgrader()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str], proceed_without_rollback: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return YoctoSnapshot(trtl, sota_cmd, self._dispatcher_callbacks, snap_num, proceed_without_rollback)

    def create_downloader(self) -> Downloader:
        logger.debug("")
        return YoctoDownloader()


class YoctoARM(ISotaOs):
    """YoctoARM class, child of ISotaOs"""

    def __init__(self, callback: DispatcherCallbacks) -> None:
        self.callback = callback

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return YoctoSetupHelper(self.callback)

    def create_rebooter(self) -> Rebooter:
        logger.debug("")
        return LinuxRebooter(self.callback)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return YoctoARMUpdater()

    def create_os_upgrader(self) -> OsUpgrader:
        logger.debug("")
        return YoctoUpgrader()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str], proceed_without_rollback: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return YoctoSnapshot(trtl, sota_cmd, self.callback, snap_num, proceed_without_rollback)

    def create_downloader(self) -> Downloader:
        logger.debug("")
        return YoctoDownloader()


class DebianBasedSotaOs(ISotaOs):
    """DebianBasedSotaOs class, child of ISotaOs"""

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        """Constructor.

        @param dispatcher_callbacks: DispatcherCallbacks instance
        """
        self._dispatcher_callbacks = dispatcher_callbacks

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return DebianBasedSetupHelper(self._dispatcher_callbacks)

    def create_rebooter(self) -> Rebooter:
        return LinuxRebooter(self._dispatcher_callbacks)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return DebianBasedUpdater()

    def create_os_upgrader(self) -> OsUpgrader:
        logger.debug("")
        return UbuntuUpgrader()  # TODO: remove--we don't support upgrade

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str], proceed_without_rollback: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner(), BTRFS)
        return DebianBasedSnapshot(trtl, sota_cmd, self._dispatcher_callbacks, snap_num, proceed_without_rollback)

    def create_downloader(self) -> Downloader:
        return DebianBasedDownloader()


class Windows(ISotaOs):
    """Windows class, child of ISotaOs"""

    def __init__(self, callback) -> None:
        """Constructor.

        @param callback: callback to Dispatcher
        """
        self.callback = callback

    def create_setup_helper(self) -> SetupHelper:
        logger.debug("")
        return WindowsSetupHelper(self.callback)

    def create_rebooter(self) -> Rebooter:
        return WindowsRebooter(self.callback)

    def create_os_updater(self) -> OsUpdater:
        logger.debug("")
        return WindowsUpdater()

    def create_os_upgrader(self) -> OsUpgrader:
        logger.debug("")
        return WindowsUpgrader()

    def create_snapshotter(self, sota_cmd: str, snap_num: Optional[str], proceed_without_rollback: bool) -> Snapshot:
        logger.debug("")
        trtl = Trtl(PseudoShellRunner())
        return WindowsSnapshot(trtl, sota_cmd, self.callback, snap_num, proceed_without_rollback)

    def create_downloader(self) -> Downloader:
        return WindowsDownloader()
