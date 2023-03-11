"""
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from enum import Enum


class Commands(Enum):
    """Enum containing supported commands in Diagnostic Agent"""
    (
        install_check,
        health_device_battery,
        check_storage,
        check_memory,
        check_network,
        container_health_check,
        swCheck

    ) = range(7)
