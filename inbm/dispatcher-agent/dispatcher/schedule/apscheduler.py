"""
    Uses APScheduler to execute scheduled tasks.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from datetime import datetime
from typing import Callable
import os

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


class APScheduler:
    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler()

    def start(self) -> None:
        """Start the scheduler"""
        logger.debug("")
        self._scheduler.start()

    def add_single_schedule_job(self, callback: Callable, schedule_date: str, manifest: str) -> None:
        """Handles the connection to the SQLite database and all database operations.

        @param callback: The function to be called.
        @param schedule_date: The schedule date.
        @param manifest: Manifest to be executed.
        """
        logger.debug("")
        self._scheduler.add_job(callback, 'date', run_date=schedule_date, args=[manifest])
