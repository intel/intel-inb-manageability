"""
    Uses APScheduler to execute scheduled tasks.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Callable

from .schedules import SingleSchedule, RepeatedSchedule
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


class APScheduler:
    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler()

    def start(self) -> None:
        """Start the scheduler"""
        logger.debug("")
        self._scheduler.start()

    def add_single_schedule_job(self, callback: Callable, single_schedule: SingleSchedule) -> None:
        """Add the job for single schedule.

        @param callback: The function to be called.
        @param single_schedule: SingleSchedule object
        """
        logger.debug("")
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

