"""
    SOTA updates factory class. Used to trigger
    package installation, updates, security updates etc
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import re
import os
from pathlib import Path
from typing import List, Optional
from abc import ABC, abstractmethod

from inbm_common_lib.utility import CanonicalUri
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import DOCKER_CHROOT_PREFIX, CHROOT_PREFIX
from inbm_common_lib.utility import get_canonical_representation_of_path

from .command_list import CommandList
from .constants import MENDER_FILE_PATH
from .converter import size_to_bytes
from .sota_error import SotaError
from ..common import uri_utilities
from ..packagemanager import irepo

logger = logging.getLogger(__name__)


# Mender commands/arguments
MENDER_COMMAND = MENDER_FILE_PATH
MENDER_MINIMIZE_LOGS_ARGUMENT = "-log-level panic"
MENDER_UPDATE_SCRIPT_EHL = "/etc/mender/scripts/ArtifactInstall_Leave_00_relabel_ext4"
MENDER_ARTIFACT_INSTALL_COMMAND = MENDER_UPDATE_SCRIPT_EHL

def mender_install_argument():
    (out, err, code) = PseudoShellRunner.run(MENDER_FILE_PATH + " -help")
    if "-install" in out or ((err is not None) and "-install" in err):
        return "-install"
    else:
        return "install"


class OsUpdater(ABC):  # pragma: no cover
    """Abstract class for handling OS update related tasks for the system."""

    def __init__(self) -> None:
        self.cmd_list: List = []

    @abstractmethod
    def update_remote_source(self, uri: Optional[CanonicalUri], repo: irepo.IRepo) -> List[str]:
        """Abstract class method to create command list to update from a remote source.

        @param uri: Original download URI, if given in manifest.
        @param repo: Directory on disk where update has been downloaded, if given in manifest.
        @return: Command list to execute to perform update.
        """
        pass

    @abstractmethod
    def update_local_source(self, file_path: str) -> List[str]:
        """Abstract class method to create command list to update from a local source.

        @param file_path: path to local file
        @return: Command list to execute to perform update.
        """
        pass

    @staticmethod
    def get_estimated_size() -> int:
        """Gets the size of the update
        @return: 0 if size is freed. Returns in bytes of size consumed
        """
        pass

    @staticmethod
    def _create_local_mender_cmd(file_path: str) -> List[str]:
        commands = [" " + MENDER_COMMAND + " " + mender_install_argument() + " " +
                    file_path + " " + MENDER_MINIMIZE_LOGS_ARGUMENT]
        return CommandList(commands).cmd_list


class DebianBasedUpdater(OsUpdater):
    """DebianBasedUpdater class, child of OsUpdater"""

    def __init__(self) -> None:
        super().__init__()

    def update_remote_source(self, uri: Optional[CanonicalUri], repo: irepo.IRepo) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Debian OS.

        @param uri: Original download URI, if given in manifest.
        @param repo: Directory on disk where update has been downloaded, if given in manifest.
        @return: Command list to execute to perform update.
        """
        logger.debug("")
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
        is_docker_app = os.environ.get("container", False)
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))
            # get all packages ready for install (requires network and does
            # not require host PID/DOCKER_CHROOT_PREFIX), then run the install locally
            # (does not require network but does require host PID/DOCKER_CHROOT_PREFIX)
            cmds = [CHROOT_PREFIX + "/usr/bin/apt-get update",  # needs network
                    CHROOT_PREFIX + "/usr/bin/apt-get -yq --download-only -f install",  # needs network
                    DOCKER_CHROOT_PREFIX + "/usr/bin/apt-get -yq -f install",  # local
                    CHROOT_PREFIX + "/usr/bin/dpkg-query -f '${binary:Package}\\n' -W",
                    CHROOT_PREFIX + "/usr/bin/dpkg --configure -a",
                    CHROOT_PREFIX + "/usr/bin/apt-get -yq --download-only upgrade",  # needs network
                    DOCKER_CHROOT_PREFIX + "/usr/bin/apt-get -yq upgrade"]  # local
        else:
            cmds = ["apt-get update",
                    "dpkg-query -f '${binary:Package}\\n' -W",
                    "dpkg --configure -a",
                    "apt-get -yq -f install",
                    "apt-get -yq upgrade"]
        return CommandList(cmds).cmd_list

    def update_local_source(self, file_path: str) -> List[str]:
        """Concrete class method to create command list to update from a local source for Debian OS.

        @param file_path: path to local file
        @return: Command list to execute to perform update.
        """
        logger.error('Local install of Debian packages is not supported.')
        return CommandList([]).cmd_list

    @staticmethod
    def get_estimated_size() -> int:
        """Gets the size of the update

        @return: Returns 0 if size is freed. Returns in bytes of size consumed
        """
        logger.debug("")
        is_docker_app = os.environ.get("container", False)
        cmd = "/usr/bin/apt-get -u upgrade --assume-no"
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))

            (upgrade, _, _) = PseudoShellRunner.run(DOCKER_CHROOT_PREFIX + cmd)
        else:
            (upgrade, _, _) = PseudoShellRunner.run(cmd)
        return DebianBasedUpdater._get_estimated_size_from_apt_get_upgrade(upgrade)

    @staticmethod
    def _get_estimated_size_from_apt_get_upgrade(upgrade_output: str) -> int:
        logger.debug("")
        output = "\n".join([k for k in upgrade_output.splitlines() if 'After this operation' in k])

        update_regex = re.search(r"(\d+(,\d+)*(\.\d+)?.(kB|B|mB|gB)).*(freed|used)", output)
        try:
            if update_regex is None:
                return 0
            size_string = update_regex.group(1)
            freed_or_used = update_regex.group(5)

            update_size = size_to_bytes(size_string.replace(',', ''))

            if freed_or_used == "used":
                return update_size
            else:
                logger.info('Update will free some size on disk')
                return 0
        except AttributeError:  # TODO(gblewis1): return/process an error--size could be > than 0
            logger.info('Update size could not be extracted!')
            return 0


class YoctoX86_64Updater(OsUpdater):
    """YoctoX86_64Updater class, child of OsUpdater"""

    def __init__(self) -> None:
        super().__init__()

    def update_remote_source(self, uri: Optional[CanonicalUri], repo: irepo.IRepo) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Yocto X86 OS.

        @param uri: Original download URI, if given in manifest.
        @param repo: Directory on disk where update has been downloaded, if given in manifest.
        @return: Command list to execute to perform update.
        """
        if uri is None:
            raise SotaError("missing URI.")
        filename = uri_utilities.uri_to_filename(uri.value)
        commands = [" " + MENDER_COMMAND + " " + mender_install_argument() + " " +
                    str(Path(repo.get_repo_path()) / filename) + " "
                    + MENDER_MINIMIZE_LOGS_ARGUMENT]

        # Only some Yocto systems need to run an additional command after running mender.
        if Path(str(MENDER_UPDATE_SCRIPT_EHL)).is_file():
            commands.append(MENDER_ARTIFACT_INSTALL_COMMAND)
        return CommandList(commands).cmd_list

    def update_local_source(self, file_path: str) -> List[str]:
        """Concrete class method to create command list to update from a local source for Yocto X86 OS.

        @param file_path: path to local file
        @return: Command list to execute to perform update.
        """
        return super()._create_local_mender_cmd(file_path)

    @staticmethod
    def get_estimated_size() -> int:
        """Gets the size of the update

        @return: Returns 0 if size is freed. Returns in bytes of size consumed
        """
        return 0


class YoctoARMUpdater(OsUpdater):
    """YoctoARMUpdater class, child of OsUpdater"""

    def __init__(self) -> None:
        super().__init__()

    def update_remote_source(self, uri: Optional[CanonicalUri], repo: irepo.IRepo) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Yocto ARM OS.

        @param uri: Original download URI, if given in manifest.
        @param repo: Directory on disk where update has been downloaded, if given in manifest.
        @return: Command list to execute to perform update.
        """
        if uri is None:
            raise SotaError("missing URI.")
        try:
            filename = uri.value[uri.value.rfind("/") + 1:]
        except IndexError:
            raise SotaError('URI ' + str(uri) + ' is improperly formatted')
        commands = [" " + MENDER_COMMAND + " " + mender_install_argument() + " " +
                    str(Path(repo.get_repo_path()) / filename) + " "
                    + MENDER_MINIMIZE_LOGS_ARGUMENT]
        return CommandList(commands).cmd_list

    def update_local_source(self, file_path: str) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Yocto ARM OS.

        @param file_path: path to local file
        @return: Command list to execute to perform update.
        """
        return super()._create_local_mender_cmd(file_path)

    @staticmethod
    def get_estimated_size() -> int:
        """Gets the size of the update

        @return: Returns 0 if size is freed. Returns in bytes of size consumed
        """
        return 0


class WindowsUpdater(OsUpdater):
    """WindowsUpdater class, child of OsUpdater"""

    def __init__(self) -> None:
        super().__init__()

    def update_remote_source(self, uri: Optional[CanonicalUri], repo: irepo.IRepo) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Windows OS.

        @param uri: Original download URI, if given in manifest.
        @param repo: Directory on disk where update has been downloaded, if given in manifest.
        @return: Command list to execute to perform update.
        """
        pass

    def update_local_source(self, file_path: str) -> List[str]:
        """Concrete class method to create command list to update from a remote source for Windows OS.

        @param file_path: path to local file
        @return: Command list to execute to perform update.
        """
        pass

    @staticmethod
    def get_estimated_size() -> int:
        """Gets the size of the update.  Stub.
        @return: Returns 0 if size is freed. Returns in bytes of size consumed
        """
        return 0
