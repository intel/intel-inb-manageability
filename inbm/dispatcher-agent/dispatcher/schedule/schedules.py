"""
    Data structure for Scheduled Manifests

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

@dataclass(init=True)
class SingleSchedule:
    """ Represents a SingleSchedule object from the Scheduled Manifest """
    start_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    manifests: list[str] = field(default_factory=list)
 
@dataclass(init=True)
class RepeatedSchedule:
    """ Represents a RepeatedSchedule object from the Scheduled Manifest """
    cron_duration: str = field(default='*')
    cron_minutes: str = field(default='*')
    cron_hours: str = field(default='*')
    cron_day_month: str = field(default='*')
    cron_month: str = field(default='*')
    cron_day_week: str = field(default='*')
    manifests: list[str] = field(default_factory=list)
    