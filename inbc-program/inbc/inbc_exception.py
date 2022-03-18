"""
    InbcException Exception module

    Copyright (C) 2020-2022 Intel Corporation
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
    VISION_AGENT_UNAVABILABLE = -3
    NODE_NOT_FOUND = -4
    NODE_UNRESPONSIVE = -5
    HOST_BUSY = -6
    XLINK_DEVICE_NOT_FOUND_OFF = -11
    XLINK_DEVICE_BUSY = -12
    XLINK_DRIVER_UNAVAILABLE = -13
    XLINK_DRIVER_ERROR = -14
