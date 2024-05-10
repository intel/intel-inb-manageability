"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
from sqlite3 import Error
from typing import Optional
from .scheduled_task import ScheduledTask
from dispatcher.dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


class SqliteManager:
    def __init__(self, db_file) -> None:
        self._db_file = db_file

    def create_task(self, task: ScheduledTask) -> None:
        """
        Create a new scheduled task
        :param task: ScheduledTask object
        """
        conn = None
        try:
            conn = sqlite3.connect(self._db_file)
            # Creating the table
            cur = conn.cursor()
            # Check if the table already exists, if not, create the table
            logger.debug("Checking if the table exist...")
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='task'")
            if cur.fetchone() is None:
                logger.debug("Table not exist. Creating the table.")
                sql = ''' CREATE TABLE task (
                            start_time text,
                            end_time text,
                            manifest text
                        ); '''
                conn.execute(sql)  # Execute the SQL command

            # Add the task
            sql = ''' INSERT INTO task(start_time, end_time, manifest)
                      VALUES(?,?,?) '''
            logger.debug(f"Adding task: {str(task.start_time), str(task.end_time), str(task.manifest)}")
            cur.execute(sql, (str(task.start_time), str(task.end_time), str(task.manifest)))
            conn.commit()
            logger.debug("Task added.")
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to database: {e}")
        finally:
            if conn:
                conn.close()
