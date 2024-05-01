"""
    Data structure for Scheduled Task

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Union

from inbm_common_lib.constants import UNKNOWN

@dataclass(init=True)
class ScheduledTask:
    immediate: bool = field(default=False)
    scheduled_time: Union[datetime, str] = field(default=UNKNOWN)
    #TODO: interval:
    manifest: str = field(default=UNKNOWN)
