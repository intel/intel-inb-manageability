"""
    Used to detect the platform Operating system to trigger updates.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from enum import Enum
from os import path
import os
import platform
from subprocess import SubprocessError
from typing import Optional

from .constants import MENDER_FILE_PATH, SYSTEM_IS_YOCTO_PATH, FORCE_YOCTO_PATH, CENTOS_VERSION_PATH
import logging

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import DOCKER_CHROOT_PREFIX

logger = logging.getLogger(__name__)


class OsType(Enum):
    """Supported Operating Systems."""
    Linux = 0
    Windows = 1


class LinuxDistType(Enum):
    """Supported Linux Distributions"""
    Ubuntu = 0
    YoctoX86_64 = 1
    YoctoARM = 2
    Deby = 3
    Debian = 4
    CentOS = 5


def verify_os_supported() -> str:
    """Return platform.system() if contained in OsType, otherwise raise ValueError
    """

    os_type = platform.system()
    if os_type in OsType.__members__:
        return os_type
    else:
        raise ValueError('Unsupported OS type.')


def get_lsb_release_name_host() -> Optional[str]:
    """Get OS name from lsb_release command. Return None on any error.
    NOTE: will look at host rather than container, if in container
    """

    try:
        is_docker_app = os.environ.get("container", False)
        if is_docker_app:
            (result, error, exit_code) = PseudoShellRunner.run(
                DOCKER_CHROOT_PREFIX + "/usr/bin/lsb_release -i -s")
        else:
            (result, error, exit_code) = PseudoShellRunner.run("lsb_release -i -s")
        if exit_code == 0:
            logger.debug("Found lsb_release -i: " + result)
            return result.replace('\n', '')
        else:
            logger.debug(
                f"(result, error, exit_code) for lsb_release command = ({result}, {error}, {exit_code})")
            logger.debug("lsb_release command failed")
            return None
    except (ValueError, OSError, SubprocessError) as e:
        logger.debug("Unable to run lsb_release; using a different method.  Error was: " + str(e))
        return None


def detect_os() -> str:
    """Detects the operating system type running on the current system
    Will detect host OS if in container only for Linux distributions that have
    lsb_release working; otherwise falls back to method that cannot see outside
    the container.
    @return: OS type
    """

    # For debug purposes, we can force the OS to be detected as Yocto
    logger.debug('Looking for {0}'.format(FORCE_YOCTO_PATH))
    if os.path.isfile(FORCE_YOCTO_PATH):
        logger.debug('Found {0}'.format(FORCE_YOCTO_PATH))
        return LinuxDistType.YoctoX86_64.name
    logger.debug('Did not find {0}'.format(FORCE_YOCTO_PATH))

    # Get os_type string if OS is supported. E.g. Linux, Windows
    os_type = verify_os_supported()

    if os_type == OsType.Linux.name:
        _, _, kernel_version, version, arch = os.uname()
        good_lsb_release_name: Optional[str] = None
        os_name: Optional[str] = None

        # Try getting name from lsb_release (should only work on Linux)
        lsb_release_name = get_lsb_release_name_host()

        if lsb_release_name is not None and lsb_release_name in LinuxDistType.__members__:
            logger.debug("Detected OS with lsb_release: " + lsb_release_name)
            os_name = lsb_release_name
        elif path.exists(SYSTEM_IS_YOCTO_PATH):
            if not path.exists(MENDER_FILE_PATH):
                raise ValueError("Yocto detected but unable to find Mender")
            if arch.startswith("arm") or arch.startswith("ARM") or arch == 'aarch64':
                os_name = LinuxDistType.YoctoARM.name
            elif arch.startswith("x86_64"):
                os_name = LinuxDistType.YoctoX86_64.name
            else:
                raise ValueError("Unsupported architecture: {}".format(str(arch)))

        if os_name is not None:
            return os_name
        else:
            raise ValueError("Unsupported OS type or unable to detect OS")
    else:  # Supported but not on Linux
        return os_type


def is_inside_container() -> bool:
    """Detects if the application is running inside container.
    @return: True if the environment is inside container; False if the environment is not inside container.
    """
    if os.environ.get("container", False):
        logger.debug("Running inside container.")
        return True
    return False
