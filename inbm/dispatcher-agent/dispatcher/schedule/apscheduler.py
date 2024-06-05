"""
    Uses APScheduler to execute scheduled tasks.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Callable

from .schedules import SingleSchedule
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
        @param schedule_date: The schedule date.
        @param manifest: Manifest to be executed.
        """
        logger.debug("")
        self._scheduler.add_job(callback, 'date', run_date=single_schedule.start_time, args=[single_schedule.manifests])
