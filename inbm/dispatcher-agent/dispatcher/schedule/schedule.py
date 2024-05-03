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

class Schedule:
    def __init__(self, db_file) -> None:
        self._db_file = db_file
            
    def _create_connection(self) -> sqlite3.Connection:
        """ create a database connection to a SQLite database """
        conn = None
        try:
            return sqlite3.connect(self._db_file)      
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to database: {e}")
        finally:
            if conn:
                conn.close()
                
    def create_task(self, task: ScheduledTask) -> Optional[int]:
        """
        Create a new scheduled task
        :param task: ScheduledTask object
        :return: PK for the scheduled task in the DB
        """
        conn = self._create_connection()
        with conn:
            sql = ''' INSERT INTO task(NULL, start_time, end_time, manifest)
                    VALUES(?,?) '''
            cur = conn.cursor()

            cur.execute(sql, (task.start_time, task.end_time, task.manifest))
            return cur.lastrowid                
                