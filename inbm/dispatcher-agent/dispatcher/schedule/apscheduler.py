"""
    Uses APScheduler to execute scheduled tasks.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import re
from typing import Callable, Union
from datetime import datetime, timedelta
from time import sleep

from .schedules import Schedule, SingleSchedule, RepeatedSchedule
from apscheduler.schedulers.background import BackgroundScheduler
from .sqlite_manager import SqliteManager
from ..constants import SCHEDULED
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


class APScheduler:
    def __init__(self, sqlite_mgr: SqliteManager) -> None:
        self._scheduler = BackgroundScheduler()
        self._sqlite_mgr = sqlite_mgr

    def start(self) -> None:
        """Start the scheduler"""
        def starting_message():
            logger.debug("Starting APScheduler")
        self._scheduler.start()
        self._scheduler.add_job(starting_message, 'date', run_date=datetime.now() + timedelta(seconds=1))
        sleep(1)


    def remove_all_jobs(self) -> None:
        """Remove all jobs."""
        logger.debug("Remove all jobs in APScheduler")
        self._scheduler.remove_all_jobs()

    def add_single_schedule_job(self, callback: Callable, 
                                single_schedule: SingleSchedule) -> None:
        """Add the job for single schedule.

        @param callback: The function to be called.
        @param single_schedule: SingleSchedule object
        """
        logger.debug("")
        if self.is_schedulable(single_schedule):
            self._sqlite_mgr.update_status(single_schedule, SCHEDULED)
            try:
                for manifest in single_schedule.manifests:
                    self._scheduler.add_job(
                        func=callback, trigger='date', run_date=single_schedule.start_time, args=[manifest])
            except (ValueError, TypeError) as err:
                raise DispatcherException(f"Please correct and resubmit scheduled request. Invalid parameter used in date expresssion to APScheduler: {err}")


    def add_repeated_schedule_job(self, callback: Callable, repeated_schedule: RepeatedSchedule) -> None:
        """Add the job for repeated schedule.

        @param callback: The function to be called.
        @param repeated_schedule: RepeatedSchedule object.
        """
        logger.debug("")
        if self.is_schedulable(repeated_schedule):
            self._sqlite_mgr.update_status(repeated_schedule, SCHEDULED)
            try:
                for manifest in repeated_schedule.manifests:
                    self._scheduler.add_job(func=callback, trigger='cron', args=[manifest],
                                            start_date=datetime.now(),
                                            end_date=self._convert_duration_to_end_time(
                                                repeated_schedule.cron_duration),
                                            minute=repeated_schedule.cron_minutes,
                                            hour=repeated_schedule.cron_hours,
                                            day=repeated_schedule.cron_day_month,
                                            month=repeated_schedule.cron_month,
                                            day_of_week=repeated_schedule.cron_day_week)
            except (ValueError, TypeError) as err:
                raise DispatcherException(f"Please correct and resubmit scheduled request. Invalid parameter used in cron expresssion to APScheduler: {err}")

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
        logger.debug(
            f"current_time={current_time}, start_time={schedule.start_time}, end_time={schedule.end_time}")

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
            # Reset the start time to current datetime + 2s buffer time.
            schedule.start_time = datetime.now() + timedelta(seconds=2)
            return True

        logger.error("The start time or current time is greater than the end time. Not scheduled.")
        return False

    def _check_repeated_schedule(self, schedule: RepeatedSchedule) -> bool:
        """Check if the schedule can be scheduled.

        @param schedule: RepeatedSchedule object
        @return: True if the check passes; False if rejected.
        """
        logger.debug(f"cron_duration={schedule.cron_duration},"
                     f"cron_minutes={schedule.cron_minutes},"
                     f"cron_hours={schedule.cron_duration},"
                     f"cron_day_month={schedule.cron_day_month},"
                     f"cron_month={schedule.cron_month},"
                     f"cron_day_week={schedule.cron_day_week}")
        
        # No negative duration
        if schedule.cron_duration[0] == "-":
            raise DispatcherException("Negative durations are not supported")

        return True

    def _convert_duration_to_end_time(self, duration: str) -> Union[str, datetime]:
        """Convert the cron duration to end time.

        @param duration: cron duration
        @return: datetime object or str
        """
        # Example of supported cron_duration are "P7D", "PT3600S"
        # Pattern to extract days or seconds
        end_time: Union[str, datetime] = duration
        if duration != "*":
            pattern = r'P(?:(\d+)D)?T?(?:(\d+)S)?'
            match = re.match(pattern, duration)
            if match:
                days = int(match.group(1)) if match.group(1) else 0
                seconds = int(match.group(2)) if match.group(2) else 0
            else:
                days = 0
                seconds = 0
            end_time = datetime.now() + timedelta(days=days, seconds=seconds)
            logger.debug(f"Repeated end_time={end_time}")
        return end_time
