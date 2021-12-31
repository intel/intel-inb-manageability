"""
    Utility for flashless files such as copy and rollback flashless files.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import logging
import shutil

from typing import List, Tuple
from inbm_vision_lib.constants import FIP_FILE, OS_IMAGE, ROOTFS, LIB_FIRMWARE_PATH, FLASHLESS_BACKUP
from inbm_common_lib.utility import remove_file
from vision.registry_manager import RegistryManager

logger = logging.getLogger(__name__)


def copy_backup_flashless_files() -> None:
    """Copy the flashless files such as thb_fip.bin, thb_os.bin and thb_rootfs.bin to FLASHLESS_BACKUP folder."""
    try:
        shutil.copy(os.path.join(LIB_FIRMWARE_PATH, FIP_FILE), FLASHLESS_BACKUP)
        shutil.copy(os.path.join(LIB_FIRMWARE_PATH, OS_IMAGE), FLASHLESS_BACKUP)
        shutil.copy(os.path.join(LIB_FIRMWARE_PATH, ROOTFS), FLASHLESS_BACKUP)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"FLASHLESS OTA FAILURE while moving files: {error}")


def rollback_flashless_files() -> None:
    """Move the backup flasless files from FLASHLESS_BACKUP to /lib/firmware when the rollback happened."""
    try:
        shutil.copy(os.path.join(FLASHLESS_BACKUP, FIP_FILE), LIB_FIRMWARE_PATH)
        shutil.copy(os.path.join(FLASHLESS_BACKUP, OS_IMAGE), LIB_FIRMWARE_PATH)
        shutil.copy(os.path.join(FLASHLESS_BACKUP, ROOTFS), LIB_FIRMWARE_PATH)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"FLASHLESS OTA FAILURE during backup files: {error}")


def remove_backup_files() -> None:
    """Remove the backup flasless files from FLASHLESS_BACKUP after OTA success."""
    try:
        remove_file(os.path.join(FLASHLESS_BACKUP, FIP_FILE))
        remove_file(os.path.join(FLASHLESS_BACKUP, OS_IMAGE))
        remove_file(os.path.join(FLASHLESS_BACKUP, ROOTFS))
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Remove backup files failed with error: {error}")


def filter_flashless_device(node_list: List[str], registry_manager: RegistryManager) -> \
        Tuple[List[str], List[str]]:
    """ Separate the node in the list into flashless and non-flashless list

    @param node_list: a list of node to be separated
    @param registry_manager: RegistryManager object that stored a list of nodes' information
    @return: a list of non-flashless node and a list of flashless node
    """
    non_flashless_node_list = node_list.copy()
    flashless_node_list = []
    for node in node_list:
        if registry_manager.is_node_flashless(node):
            flashless_node_list.append(node)
            non_flashless_node_list.remove(node)
    logger.debug("Flashless device: {0}".format(
        flashless_node_list if flashless_node_list else None))
    return non_flashless_node_list, flashless_node_list
