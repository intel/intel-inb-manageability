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
    """Enum containing INBC error with code"""
    SUCCESS = 0
    FAIL = -1
    COMMAND_TIMED_OUT = -2
    HOST_BUSY = -6
