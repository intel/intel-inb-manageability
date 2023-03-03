"""
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum


class ConfigDbs(Enum):
    """DBS configuration settings.
    ON - DBS is on and will kill/remove flagged containers and images
    OFF - DBS is off and will not run the DBS script
    WARN - DBS is on but will not kill/remove any flagged containers and images
    """

    ON = ["ON", "on"]
    OFF = ["OFF", "off"]
    WARN = ["WARN", "warn"]
