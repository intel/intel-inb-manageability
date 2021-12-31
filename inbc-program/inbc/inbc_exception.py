"""
    InbcException Exception module

    Copyright (C) 2020-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from enum import Enum


class InbcException(Exception):
    """InbcException exception module"""
    pass


class InbcCode(Enum):
    """Enum containing Inbc error with code"""
    SUCCESS = 0
    FAIL = -1
    COMMAND_TIMED_OUT = -2
    BITCREEK_VISION_AGENT_UNAVABILABLE = -3
    BITCREEK_NODE_NOT_FOUND = -4
    BITCREEK_NODE_UNRESPONSIVE = -5
    BITCREEK_HOST_BUSY = -6
    XLINK_DEVICE_NOT_FOUND_OFF = -11
    XLINK_DEVICE_BUSY = -12
    XLINK_DRIVER_UNAVAILABLE = -13
    XLINK_DRIVER_ERROR = -14
