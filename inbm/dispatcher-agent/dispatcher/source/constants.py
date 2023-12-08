"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum, unique


@unique
class SourceCmdType(Enum):
    """Source Type to manipulate
    OS - Source files related to the operating system
    Application - Source files related to installed applications
    """

    OS = ["os"]
    Application = ["application"]


@unique
class OsType(Enum):
    """Supported Operating Systems."""
    Ubuntu = 0
    # Windows = 1 # Not currently supported
