"""
    Uses APScheduler to execute scheduled tasks.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Callable
from datetime import datetime

from .schedules import Schedule, SingleSchedule, RepeatedSchedule
from apscheduler.schedulers.background import BackgroundScheduler
from .sqlite_manager import SqliteManager
from ..constants import SCHEDULED

logger = logging.getLogger(__name__)


class APScheduler:
    def __init__(self, sqlite_mgr: SqliteManager) -> None:
        self._scheduler = BackgroundScheduler()
        self._sqlite_mgr = sqlite_mgr

    def start(self) -> None:
        """Start the scheduler"""
        logger.debug("Starting APScheduler")
        self._scheduler.start()

    def add_single_schedule_job(self, callback: Callable, single_schedule: SingleSchedule) -> None:
        """Add the job for single schedule.

        @param callback: The function to be called.
        @param single_schedule: SingleSchedule object
        """
        logger.debug("")
        if self.is_schedulable(single_schedule):
            self._sqlite_mgr.update_status(single_schedule, SCHEDULED)
            for manifest in single_schedule.manifests:
                self._scheduler.add_job(callback, 'date', run_date=single_schedule.start_time, args=[manifest])

    def add_repeated_schedule_job(self, callback: Callable, repeated_schedule: RepeatedSchedule) -> None:
        """Add the job for repeated schedule.

        @param callback: The function to be called.
        @param repeated_schedule: RepeatedSchedule object.
        """
        logger.debug("")
        for manifest in repeated_schedule.manifests:
            logger.debug("To be implemented.")

    def is_schedulable(self, schedule: Schedule) -> bool:
        """Check if the schedule can be scheduled.

        @param schedule: The function to be called.
        @return: True if to be scheduled; False if not to schedule.
        """
        if isinstance(schedule, SingleSchedule):
            return self._check_single_schedule(schedule)
        elif isinstance(schedule, RepeatedSchedule):
            return self._check_repeated_schedule(schedule)
        else:
            logger.error("Schedule type is neither a SingleSchedule nor a RepeatedSchedule object.")
        return False

    def _check_single_schedule(self, schedule: SingleSchedule) -> bool:
        """Check if the schedule can be scheduled.

        @param schedule: SingleSchedule object
        @return: True if the start time fulfill the requirement; False if start time fails the requirement.
        """
        current_time = datetime.now()
        logger.debug(f"current_time={current_time}, start_time={schedule.start_time}, end_time={schedule.end_time}")

        # If the start time is greater than the end time, the schedule is rejected.
        if schedule.start_time and schedule.end_time and \
                schedule.start_time > schedule.end_time:
            logger.error("The start time is greater than the end time. Will not schedule.")
            return False

        # If the start time is greater than the current time and it is within the end time, the schedule
        # is accepted.
        if schedule.start_time and schedule.end_time and \
                schedule.start_time > current_time < schedule.end_time:

            return True

        # If the start time is lower than the current time and the current time is within the end time, the schedule
        # run immediately.
        if schedule.start_time and schedule.end_time and \
                schedule.start_time < current_time < schedule.end_time:
            # Reset the start time to current datetime.
            schedule.start_time = datetime.now()
            return True

        logger.error("The start time or current time is greather than end time. Will not schedule")
        return False

    def _check_repeated_schedule(self, schedule: RepeatedSchedule) -> bool:
        """Check if the start time is still within the end time.

        @param schedule: RepeatedSchedule object
        @return: True if start time doesn't exceed end time; False if start time exceeds end time.
        """
        return False
