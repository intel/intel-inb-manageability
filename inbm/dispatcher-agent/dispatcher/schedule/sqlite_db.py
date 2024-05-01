"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import sqlite3
from sqlite3 import Error
from schedule.scheduled_task import ScheduledTask

class Schedule:
    def __init__(self, db_file) -> None:
        self._db_file = db_file
            
    def _create_connection(self) -> None:
        """ create a database connection to a SQLite database """
        conn = None
        try:
            self.connection = sqlite3.connect(self.db_file)      
        except Error as e:
            print(e)
        finally:
            if conn:
                conn.close()
                
    def create_task(self, task: ScheduledTask) -> int:
        """
        Create a new scheduled task
        :param task: ScheduledTask object
        :return: PK for the scheduled task in the DB
        """
        conn = self.create_connection()
        with conn:
            sql = ''' INSERT INTO task(NULL, scheduled_time, manifest)
                    VALUES(?,?) '''
            cur = self.conn.cursor()

            cur.execute(sql, (task.scheduled_time, task.manifest))
            return cur.lastrowid                
                