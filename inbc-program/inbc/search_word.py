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
            return True
    return False

