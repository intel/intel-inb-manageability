
# -*- coding: utf-8 -*-
"""
    Calculates the free space on the disk

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_vision_lib.shell_runner import PseudoShellRunner
from .constant import VAR_DIR
import logging
import re

import psutil

logger = logging.getLogger(__name__)


def get_free_space():
    """This is the helper function to co-ordinate all free disk space determining operations

    @return: return in bytes(integer)
    """
    fs = _get_fstype_root_part()
    logger.info('Detecting file system for root mount point to be {}'.format(fs))
    return _calculate_btrfs_free_space() if fs == 'btrfs' else _get_non_btrfs_space()


def _get_fstype_root_part():
    """Determines type of file system for / partition

    @return : string representation whether 'ext' or 'btrfs'
    """
    # psutil.disk_partitions needs to with all=True when working with in-memory file systems
    # When all=False it only returns physical disk devices and misses Docker's
    # AUFS or overlay FS
    file_systems_tuple = psutil.disk_partitions(all=True)
    logger.debug("psutil.disk_partitions returns %s" % (file_systems_tuple,))
    fs_list = [x.fstype for x in file_systems_tuple if x.mountpoint == '/']
    fs_list.sort()
    return fs_list[-1]


def _calculate_btrfs_free_space():
    """Retrieves the min free space(conservative limit) allowed for BTRFS

    @return : return in bytes(integer) the min free space for BTRFS, if it fails
    to retrieve, returns default ps_utils value
    """
    (out, err, code) = PseudoShellRunner.run('btrfs filesystem usage -b /')

    try:
        if code == 0:
            logger.debug('The output of BTRFS filesystem usage command: {}'.format(str(out)))
            fsregex = re.search("min: \d+", out)
            if not fsregex:
                logger.debug(
                    'Failed to determine free space for BTRFS..falling back to default implementation')
                return _get_non_btrfs_space()
            free_space = fsregex.group(0)
            return int(free_space.split()[1])
        else:
            logger.debug(
                'Failed to determine free space for BTRFS..falling back to default implementation')
            return _get_non_btrfs_space()
    except (re.error, KeyError):
        logger.debug(
            'Failed to determine free space for BTRFS..falling back to default implementation')
        return _get_non_btrfs_space()


def _get_non_btrfs_space():
    return psutil.disk_usage(VAR_DIR).free


def get_free_memory() -> int:
    """This is the helper function to check and return free memory on the system

    @return: return in bytes(integer)
    """
    return psutil.virtual_memory().free
