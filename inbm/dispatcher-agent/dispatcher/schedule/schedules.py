"""
    Data structure for Scheduled Manifests

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass(init=True)
class SingleSchedule:
    start_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    manifests: List[str] = field(default_factory=list)
 
@dataclass(init=True)
class RepeatedSchedule:
    cron_duration: str = field(default='*')
    cron_minutes: str = field(default='*')
    cron_hours: str = field(default='*')
    cron_day_month: str = field(default='*')
    cron_month: str = field(default='*')
    cron_day_week: str = field(default='*')
    manifests: List[str] = field(default_factory=list)
    