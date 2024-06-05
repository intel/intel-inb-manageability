"""
    Data structure for Scheduled Manifests

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class Schedule:
    """ Represents a Base class for schedule objects """
    request_id: str
    id: Optional[int] = field(default=None)    


@dataclass
class SingleSchedule(Schedule):
    """ Represents a SingleSchedule object from the Scheduled Manifest """ 
    start_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)
    manifests: List[str] = field(default_factory=list)
 
@dataclass
class RepeatedSchedule(Schedule):
    """ Represents a RepeatedSchedule object from the Scheduled Manifest """
    cron_duration: str = field(default='*')
    cron_minutes: str = field(default='*')
    cron_hours: str = field(default='*')
    cron_day_month: str = field(default='*')
    cron_month: str = field(default='*')
    cron_day_week: str = field(default='*')
    manifests: List[str] = field(default_factory=list)

@dataclass
class SingleScheduleManifest:
    """ Represents a SingleScheduleManifest object from the Scheduled Manifest """
    priority: int
    schedule_id: int
    manifest_id: int