"""
    Utilities for INBC tool

    Copyright (C) 2020-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import shutil
from typing import List
from pathlib import Path

from .constants import VISION_SERVICE_PATH
from .inbc_exception import InbcException

from inbm_vision_lib.constants import CACHE_MANAGEABILITY


def search_keyword(payload: str, words: List[str]) -> bool:
    """Stop INBC after receiving expected response from vision-agent

    @param payload: MQTT message received from vision-agent
    @param words: expected keywords in the message
    @return: True if keyword found, False if keyword not found in message
    """
    for word in words:
        if payload.find(word) >= 0:
            return True
    return False


def copy_file_to_target_location(usr_path: Path, target_dir: str) -> str:
    """Method to copy file to target location.  This is only used for HDDL.

    @param usr_path: location of file to be moved
    @param target_dir: location of file moving to
    """
    # If it is inside IT, modify the target path to IT path.
    with open(VISION_SERVICE_PATH, 'r') as vision_service_file:
        if "XLINK_SIMULATOR=False" in vision_service_file.read():
            # Not inside IT environment
            target_path = Path(os.path.join(target_dir, usr_path.name))
        else:
            target_path = Path(os.path.join(CACHE_MANAGEABILITY, usr_path.name))

    if usr_path.absolute() != target_path:
        if not usr_path.is_file():
            raise InbcException("No file found at {0}".format(usr_path))
        if usr_path.is_symlink():
            raise InbcException("Security error: Path is a symlink.")
        if target_path.is_file():
            target_path.unlink()
            shutil.copy2(usr_path, target_path)
        else:
            shutil.copy2(usr_path, target_path)
    return str(target_path)


def is_vision_agent_installed() -> bool:
    """Checks if the device has vision-agent present
    @return: True if vision-agent is installed on system; otherwise, False."""

    return True if os.path.exists('/usr/bin/vision') else False
