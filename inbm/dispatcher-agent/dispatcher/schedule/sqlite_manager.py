"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
from sqlite3 import Error
from typing import Union
from .schedules import SingleSchedule, RepeatedSchedule
from ..dispatcher_exception import DispatcherException
from ..constants import UDM_DB_FILE

logger = logging.getLogger(__name__)


class SqliteManager:
    def __init__(self, db_file=UDM_DB_FILE) -> None:
        self._db_file = db_file

    def create_task(self, task: Union[SingleSchedule, RepeatedSchedule]) -> None:
        """
        Create a new scheduled task
        :param task: SingleSchedule or RepeatedSchedule object
        """
        conn = None
        try:
            conn = sqlite3.connect(self._db_file)
            if isinstance(task, SingleSchedule):
                self._create_single_schedule_task(task, conn)
            elif isinstance(task, RepeatedSchedule):
                self._create_repeated_schedule_task(task, conn)
            else:
                print("Task is neither a SingleSchedule nor a RepeatedSchedule object.")
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to database: {e}")
        finally:
            if conn:
                conn.close()

    def _create_single_schedule_task(self, task: SingleSchedule, conn: sqlite3.Connection) -> None:
        # Creating the table
        cur = conn.cursor()
        # Check if the table already exists, if not, create the table
        logger.debug("Checking if the table exist...")
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='single_task'")
        if cur.fetchone() is None:
            logger.debug("Table not exist. Creating the table.")
            sql = ''' CREATE TABLE single_task (
                                    request_id text,
                                    start_time text,
                                    end_time text,
                                    manifests text
                                ); '''
            conn.execute(sql)  # Execute the SQL command

        # Add the task
        for manifest in task.manifests:
            sql = ''' INSERT INTO single_task(request_id, start_time, end_time, manifests)
                                  VALUES(?,?,?,?) '''
            logger.debug(f"Adding task: {str(task.request_id), str(task.start_time), str(task.end_time), str(manifest)}")
            cur.execute(sql, (str(task.request_id), str(task.start_time), str(task.end_time), str(manifest)))
            conn.commit()
        logger.debug("Task added.")

    def _create_repeated_schedule_task(self, task: RepeatedSchedule, conn: sqlite3.Connection) -> None:
        # Creating the table
        cur = conn.cursor()
        # Check if the table already exists, if not, create the table
        logger.debug("Checking if the table exist...")
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='repeated_task'")
        if cur.fetchone() is None:
            logger.debug("Table not exist. Creating the table.")
            sql = ''' CREATE TABLE repeated_task (
                                    request_id text,
                                    cron_duration text,
                                    cron_minutes text,
                                    cron_hours text,
                                    cron_day_month text,
                                    cron_month text,
                                    cron_day_week text,
                                    manifests text
                                ); '''
            conn.execute(sql)  # Execute the SQL command

        # Add the task
        for manifest in task.manifests:

            sql = ''' INSERT INTO repeated_task(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week, manifests)
                                  VALUES(?, ?,?,?,?,?,?,?) '''
            logger.debug(f"Adding task: {str(task.request_id), str(task.cron_duration), str(task.cron_minutes), str(task.cron_hours), str(task.cron_day_month), str(task.cron_month), str(task.cron_day_week),str(manifest)}")
            cur.execute(sql, (str(task.request_id), str(task.cron_duration), str(task.cron_minutes), str(task.cron_hours), str(task.cron_day_month), str(task.cron_month), str(task.cron_day_week),str(manifest)))
            conn.commit()
        logger.debug("Task added.")