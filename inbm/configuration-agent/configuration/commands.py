"""
    Commands supported by Configuration Agent

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from enum import Enum


class Commands(Enum):
    """Enum containing supported commands in Configuration Agent"""
    (
        get_element,
        set_element,
        load,
        append,
        remove
    ) = range(5)
