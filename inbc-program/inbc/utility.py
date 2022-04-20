"""
    Utilities for INBC tool

    Copyright (C) 2020-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import psutil
from typing import List
from pathlib import Path

from .constants import VISION_SERVICE_PATH, VISION_BINARY_PATH, VISION
from .inbc_exception import InbcException

from inbm_common_lib.utility import copy_file
from inbm_vision_lib.constants import CACHE_MANAGEABILITY


def search_keyword(payload: str, words: List[str]) -> bool:
    """Stop INBC after receiving expected response from vision-agent

    @param payload: MQTT message received from vision-agent
    @param words: expected keywords in the message
    @return: True if keyword found, False if keyword not found in message
    """
    for word in words:
        if payload.find(word) >= 0:
            print("True=========================")
            return True
    print("False=========================")
    return False


def copy_file_to_target_location(usr_path: Path, target_dir: str) -> str:
    """Method to copy file to target location.  This is only used for HDDL.

    @param usr_path: source file location
    @param target_dir: destination directory
    """
    # If it is inside IT, modify the target path to IT path.
    with open(VISION_SERVICE_PATH, 'r') as vision_service_file:
        if "XLINK_SIMULATOR=False" in vision_service_file.read():
            # Not inside IT environment
            target_path = Path(os.path.join(target_dir, usr_path.name))
        else:
            target_path = Path(os.path.join(CACHE_MANAGEABILITY, usr_path.name))

    if usr_path.absolute() != target_path:
        try:
            copy_file(str(usr_path), str(target_path))
        except IOError as e:
            raise InbcException(f"{e}")
    return str(target_path)


def is_vision_agent_installed() -> bool:
    """Checks if the device has vision-agent present

    @return: True if vision-agent is installed on system; otherwise, False.
    """

    return True if os.path.exists(VISION_BINARY_PATH) else False


def is_vision_agent_active() -> bool:
    """Checks to see if the Vision process is running

    @return: True is vision is running on system; otherwise, False.
    """
    for p in psutil.process_iter(['name']):
        try:
            if VISION in p.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
    return False
