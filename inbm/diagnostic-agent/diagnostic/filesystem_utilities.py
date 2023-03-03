"""
    Filesystem utilities--e.g., calculate free space on a filesystem.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import platform
import re
import psutil
import os

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import CHROOT_PREFIX

logger = logging.getLogger(__name__)


def get_free_space(path: str) -> int:
    """Get free space at a particular path
    @param path: path to check

    @return: free space in bytes
    """

    if platform.system() == 'Windows':
        result = psutil.disk_usage(path).free
    else:
        mount_point = "/"  # FIXME: need a way to determine correct mount point for path
        fs = _get_filesystem_type(mount_point)
        logger.info('Detecting file system for {} (mount point {}) to be {}'.format(
            path, mount_point, fs))
        result = _calculate_btrfs_free_space(path) if fs == 'btrfs' else _get_non_btrfs_space(path)

    return result


def _calculate_btrfs_free_space(path: str) -> int:
    """Retrieves the min free space(conservative limit) allowed for BTRFS

    @param path: path to check space

    @return : return in bytes(integer) the min free space for BTRFS, if it fails
    to retrieve, returns default ps_utils value
    """

    # FIXME: we need a way to figure out a mount point corresponding to the path.

    try:
        is_docker_app = os.environ.get("container", False)
        cmd = 'btrfs filesystem usage -b /'
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))
            (out, err, code) = PseudoShellRunner.run(CHROOT_PREFIX + cmd)
        else:
            (out, err, code) = PseudoShellRunner.run(cmd)
        if code == 0:
            logger.debug('The output of BTRFS filesystem usage command: {}'.format(str(out)))
            fsregex = re.search(r"min: (\d+)", out, re.MULTILINE)
            if not fsregex:
                logger.debug(
                    'Failed to determine free space for BTRFS..falling back to default implementation')
                return _get_non_btrfs_space(path)
            free_space = fsregex.group(1)
            return int(free_space)
        else:
            logger.debug(
                'Failed to determine free space for BTRFS..falling back to default implementation')
            return _get_non_btrfs_space(path)
    except (re.error, KeyError, IOError):
        logger.debug(
            'Failed to determine free space for BTRFS..falling back to default implementation')
    return _get_non_btrfs_space(path)


def _get_non_btrfs_space(path: str) -> int:
    result = psutil.disk_usage(path).free
    logger.debug(f"Free space (non-BTRFS method) at {path} is {result}")

    return result


def _get_filesystem_type(mount_point: str) -> str:
    # type (str) -> str
    """Determines type of file system for a given mount point

    @param mount_point: mount point

    @return : string representation whether 'ext' or 'btrfs'
    """
    # psutil.disk_partitions needs to with all=True when working with in-memory file systems
    # When all=False it only returns physical disk devices and misses Docker's
    # AUFS or overlay FS
    file_systems_tuple = psutil.disk_partitions(all=True)
    logger.debug("psutil.disk_partitions returns %s" % (file_systems_tuple,))
    fs_list = [x.fstype for x in file_systems_tuple if x.mountpoint == mount_point]
    fs_list.sort()
    return fs_list[-1]
