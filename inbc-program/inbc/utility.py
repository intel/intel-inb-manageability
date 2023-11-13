"""
    Utilities for INBC tool

    Copyright (C) 2020-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import Any, List


def search_keyword(payload: Any, words: List[str]) -> bool:
    """Stop INBC after receiving expected response

    @param payload: MQTT message received from vision-agent
    @param words: expected keywords in the message
    @return: True if keyword found, False if keyword not found in message
    """
    for word in words:
        if payload.find(word) >= 0:
            return True
    return False
