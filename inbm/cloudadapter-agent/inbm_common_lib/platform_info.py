"""
    Data structure for Platform Information

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Union

from inbm_common_lib.constants import UNKNOWN


@dataclass(init=True)
class PlatformInformation:
    bios_release_date: Union[datetime, str] = field(default=UNKNOWN)
    bios_vendor: str = field(default=UNKNOWN)
    bios_version: str = field(default=UNKNOWN)
    platform_mfg: str = field(default="")
    platform_product: str = field(default="")
