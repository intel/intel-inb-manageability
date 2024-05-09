"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import sqlite3
from sqlite3 import Error
from typing import Optional
from .scheduled_task import ScheduledTask
from dispatcher.dispatcher_exception import DispatcherException

class SqliteManager:
    def __init__(self, db_file) -> None:
        self._db_file = db_file
        self._conn = self._create_connection()
        self.create_table()
            
    def _create_connection(self) -> sqlite3.Connection:
        """ create a database connection to a SQLite database """
        conn = None
        try:
            conn = sqlite3.connect(self._db_file)
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to database: {e}")
        return conn

    def create_table(self) -> None:
        """
        Method to create a table in the database.
        """
        try:
            cur = self._conn.cursor()
            # Check if the table already exists, if not, create the table
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='task'")
            if cur.fetchone() is None:
                sql = ''' CREATE TABLE task (
                            start_time text,
                            end_time text,
                            manifest text
                        ); '''
                self._conn.execute(sql)  # Execute the SQL command
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error creating table in database: {e}")

    def create_task(self, task: ScheduledTask) -> None:
        """
        Create a new scheduled task
        :param task: ScheduledTask object
        """
        try:
            with self._conn:
                sql = ''' INSERT INTO task(start_time, end_time, manifest)
                        VALUES(?,?,?) '''
                self._conn.execute(sql, (task.start_time, task.end_time, task.manifest))
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to database: {e}")
        finally:
            if self._conn:
                self._conn.close()
