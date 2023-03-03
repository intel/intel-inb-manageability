"""
    Dataclass for the diagnostic agent's config keys. This data class
    consists of the lower, upper and default values associated with the 
    config keys.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from dataclasses import dataclass


@dataclass
class ConfigKey:
    name: str
    lower_value: int
    upper_value: int
    config_value: int
