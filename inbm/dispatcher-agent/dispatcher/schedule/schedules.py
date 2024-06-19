"""
    Data structure for Scheduled Manifests

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


@dataclass
class Schedule:
    """ Represents a Base class for schedule objects """
    request_id: str
    schedule_id: Optional[int] = field(default=None)
    # priority, schedule_id, job_id from DB
    job_id: Optional[Tuple[int, int, int]] = field(default=None)
    manifests: List[str] = field(default_factory=list)


@dataclass
class SingleSchedule(Schedule):
    """ Represents a SingleSchedule object """
    start_time: Optional[datetime] = field(default=None)
    end_time: Optional[datetime] = field(default=None)


@dataclass
class RepeatedSchedule(Schedule):
    """ Represents a RepeatedSchedule object """
    cron_duration: str = field(default='*')
    cron_minutes: str = field(default='*')
    cron_hours: str = field(default='*')
    cron_day_month: str = field(default='*')
    cron_month: str = field(default='*')
    cron_day_week: str = field(default='*')


@dataclass
class ScheduledJob:
    priority: int
    schedule_id: int
    task_id: int
    status: Optional[str] = field(default=None)
