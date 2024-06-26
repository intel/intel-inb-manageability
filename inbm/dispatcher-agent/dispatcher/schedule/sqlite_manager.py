"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
import os
import stat

from datetime import datetime
from typing import List

from inbm_common_lib.utility import get_canonical_representation_of_path

from .schedules import SingleSchedule, RepeatedSchedule, Schedule
from ..dispatcher_exception import DispatcherException
from ..constants import SCHEDULER_DB_FILE, SCHEDULED

logger = logging.getLogger(__name__)


class SqliteManager:
    def __init__(self, db_file=SCHEDULER_DB_FILE) -> None:
        """Handles the connection to the SQLite database and all database operations.

        @param db_file: The path to the SQLite database file.  Defaults to SCHEDULER_DB_FILE.
        """
        self._db_file = get_canonical_representation_of_path(db_file)
        # Create the DB if it doesn't exist
        self._create_db()

        try:
            with sqlite3.connect(self._db_file, check_same_thread=False) as conn:
                self._conn = conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to Dispatcher Schedule database: {e}")
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")

        try:
            self._cursor = self._conn.cursor()
        except sqlite3.Error as e:
            logger.error(f"Error creating cursor: {e}")
            self._conn.close()
            raise DispatcherException(f"Error creating cursor: {e}")

        self._create_tables_if_not_exist()

    def close(self) -> None:
        """Close the connection to the SQLite database."""
        self._cursor.close()
        self._conn.close()

    def __del__(self) -> None:
        """Close the connection to the SQLite database."""
        self.close()

    def clear_database(self) -> None:
        """Clear the database of all data."""
        try:
            self._conn.execute('BEGIN')
            self._conn.execute('DELETE FROM single_schedule_job;')
            self._conn.execute('DELETE FROM repeated_schedule_job;')
            self._conn.execute('DELETE FROM single_schedule;')
            self._conn.execute('DELETE FROM repeated_schedule;')
            self._conn.execute('DELETE FROM job;')
            self._conn.execute('COMMIT')
        except sqlite3.Error as e:
            self._conn.execute('ROLLBACK')
            logger.error(f"Error clearing database: {e}")
            raise DispatcherException(f"Error clearing database: {e}")

    def _create_db(self) -> None:
        # Create database file if not exist
        if self._db_file != ":memory:" and not os.path.exists(self._db_file):
            logger.info(f"Database file doesn't exist. Creating the file.")
            # Set permission of the file (rw for owner and group)
            mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP
            fd = os.open(self._db_file, os.O_CREAT | os.O_WRONLY, mode)
            os.close(fd)

    def get_all_single_schedules_in_priority_order(self) -> List[SingleSchedule]:
        """
        Get all the SingleSchedule and arrange them by priority in ascending order.
        @return: List of SingleSchedule object by priority in ascending order
        """
        try:
            sql = ''' SELECT ssj.priority, ssj.schedule_id, ssj.task_id, j.job_id FROM single_schedule_job ssj  JOIN job j ON ssj.task_id=j.task_id WHERE ssj.status IS NULL ORDER BY priority ASC; '''
            self._cursor.execute(sql)
            rows = self._cursor.fetchall()
            ss: List[SingleSchedule] = []
            for row in rows:
                single_schedule = self._select_single_schedule_by_id(str(row[1]))
                single_schedule.manifests = [self._select_job_by_task_id(str(row[2]))]
                single_schedule.job_id = str(row[3])
                single_schedule.priority = row[0]
                single_schedule.task_id = row[2]
                ss.append(single_schedule)
            return ss    
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error in getting the all single schedules from database: {e}")

    def get_all_repeated_schedules_in_priority_order(self) -> List[RepeatedSchedule]:
        """
        Get all the RepeatedSchedule and arrange them by priority in ascending order.
        @return: List of RepeatedSchedule object by priority in ascending order
        """
        try:
            sql = ''' SELECT rsj.priority, rsj.schedule_id, rsj.task_id, j.job_id FROM repeated_schedule_job rsj JOIN job j ON rsj.task_id=j.task_id WHERE rsj.status IS NULL ORDER BY priority ASC; '''

            self._cursor.execute(sql)
            rows = self._cursor.fetchall()
            rs: List[RepeatedSchedule] = []
            for row in rows:
                repeated_schedule = self._select_repeated_schedule_by_id(str(row[1]))
                repeated_schedule.manifests = [self._select_job_by_task_id(str(row[2]))]
                repeated_schedule.job_id = str(row[3])
                repeated_schedule.priority = row[0]
                repeated_schedule.task_id = row[2]
                rs.append(repeated_schedule)
            return rs
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error in getting the all repeated schedules from database: {e}")

    def _select_job_by_task_id(self, task_id: str) -> str:
        """Get the job stored in database by task id.
        @param id: row index
        @return: job
        """
        sql = ''' SELECT manifest FROM job WHERE rowid=?; '''
        self._cursor.execute(sql, (task_id,))
        row = self._cursor.fetchone()
        manifest = row[0]
        logger.debug(f"id={task_id}, manifest={manifest}")
        return manifest

    def _select_single_schedule_by_id(self, schedule_id: str) -> SingleSchedule:
        """Get the single schedule stored in database by id.
        @param id: row index
        @return: SingleSchedule object
        """
        sql = ''' SELECT request_id, start_time, end_time FROM single_schedule WHERE rowid=?; '''
        self._cursor.execute(sql, (schedule_id,))
        result = self._cursor.fetchone()
        request_id = result[0]
        start_time = datetime.fromisoformat(result[1])

        if result[2]:
            end_time = datetime.fromisoformat(result[2])
        else:
            end_time = None

        logger.debug(
            f"schedule_id={schedule_id}, request_id={request_id}, start_time={start_time}, end_time={end_time}")
        return SingleSchedule(schedule_id=int(schedule_id), request_id=request_id, start_time=start_time, end_time=end_time)

    def _select_repeated_schedule_by_id(self, schedule_id: str) -> RepeatedSchedule:
        """Get the repeated schedule stored in database by schedule_id.
        @param id: row index
        @return: RepeatedSchedule object
        """
        sql = ''' SELECT request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week FROM repeated_schedule WHERE rowid=?; '''
        self._cursor.execute(sql, (schedule_id,))
        result = self._cursor.fetchone()

        request_id = result[0]
        cron_duration = result[1]
        cron_minutes = result[2]
        cron_hours = result[3]
        cron_day_month = result[4]
        cron_month = result[5]
        cron_day_week = result[6]

        logger.debug(f"schedule_id={schedule_id}, request_id={request_id}, cron_duration={cron_duration}, cron_minutes={cron_minutes}, cron_hours={cron_hours},"
                     f" cron_day_month={cron_day_month}, cron_month={cron_month}, cron_day_week={cron_day_week}")

        return RepeatedSchedule(schedule_id=int(schedule_id),
                                request_id=request_id,
                                cron_duration=cron_duration,
                                cron_minutes=cron_minutes,
                                cron_hours=cron_hours,
                                cron_day_month=cron_day_month,
                                cron_month=cron_month,
                                cron_day_week=cron_day_week)

    def update_status(self, schedule: Schedule, status: str) -> None:
        """
        Set the schedule status in the database.
        @param schedule: SingleSchedule or RepeatedSchedule object
        @param status: status to be set
        """
        try:
            sql = ""
            if isinstance(schedule, SingleSchedule):
                sql = ''' UPDATE single_schedule_job SET status = ? WHERE priority = ? AND schedule_id = ? AND task_id = ?; '''
            elif isinstance(schedule, RepeatedSchedule):
                sql = ''' UPDATE repeated_schedule_job SET status = ? WHERE priority = ? AND schedule_id = ? AND task_id = ?; '''

            if schedule.task_id != -1:
                logger.debug(f"Update status in database to {status} with schedule_id={schedule.schedule_id}, task_id={schedule.task_id}")
                self._cursor.execute(
                    sql, (status, schedule.priority, schedule.schedule_id, schedule.task_id))
                self._conn.commit()
            else:
                logger.error("Unable to update status in database as the task ID is not set.")
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error to update status in Dispatcher Schedule database: {e}")

    def create_schedule(self, schedule: Schedule) -> None:
        """
        Create a new schedule in the database.
        @param schedule: SingleSchedule or RepeatedSchedule object
        """
        try:
            if isinstance(schedule, SingleSchedule):
                self._create_single_schedule(schedule)
            elif isinstance(schedule, RepeatedSchedule):
                self._create_repeated_schedule(schedule)
            else:
                logger.error(
                    "Schedule type is neither a SingleSchedule nor a RepeatedSchedule object.")
        except (sqlite3.Error) as e:
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")

    def _create_single_schedule(self, ss: SingleSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(
            f"Execute -> INSERT INTO single_schedule(request_id, start_time, end_time) VALUES({ss.request_id}{ss.start_time}{ss.end_time})")

        sql = ''' INSERT INTO single_schedule(request_id, start_time, end_time)
                                VALUES(?,?,?); '''
        start_time = None if not ss.start_time else str(ss.start_time)
        end_time = None if not ss.end_time else str(ss.end_time)
        try:
            self._conn.execute('BEGIN')
            self._cursor.execute(sql, (ss.request_id, start_time, end_time))
            schedule_id = self._cursor.lastrowid
            if not schedule_id:
                raise DispatcherException("No schedule id was added to the single_schedule table.")

            logger.debug(
                f"Added schedule with id: {str(schedule_id)}, request_id: {ss.request_id}, start_time: {start_time}, end_time: {ss.end_time}")

            if ss.job_id:
                # Add the jobs to the job table
                task_ids = self._insert_job(ss.job_id, ss.manifests)
                # Add the schedule_id and job_id to the single_schedule_job table
                self._insert_single_schedule_jobs(schedule_id, task_ids)

            self._conn.commit()
        except (sqlite3.Error) as e:
            self._conn.rollback()
            self._cursor.close()
            logger.error(f"Transaction failed: {str(e)}")
            raise DispatcherException(f"Transaction failed: {str(e)}")

    def _create_repeated_schedule(self, rs: RepeatedSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(
            f"Execute -> INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week) VALUES({rs.request_id}, {rs.cron_duration}, {rs.cron_minutes}, {rs.cron_hours}, {rs.cron_day_month}, {rs.cron_month}, {rs.cron_day_week})")

        sql = ''' INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week)
                                VALUES(?,?,?,?,?,?,?); '''
        try:
            self._conn.execute('BEGIN')
            self._cursor.execute(sql, (rs.request_id,
                                       rs.cron_duration,
                                       rs.cron_minutes,
                                       rs.cron_hours,
                                       rs.cron_day_month,
                                       rs.cron_month,
                                       rs.cron_day_week,))
            schedule_id = self._cursor.lastrowid
            if not schedule_id:
                raise DispatcherException(
                    "No schedule id was added to the repeated_schedule table.")

            logger.debug(f"Added repeated schedule with id: {str(schedule_id)}, request_id:{rs.request_id}, job_id:{rs.job_id}, cron_duration: {rs.cron_duration}, cron_minutes: {rs.cron_minutes}, cron_hours: {rs.cron_hours}, cron_day_month: {rs.cron_day_month}, cron_month: {rs.cron_month}, cron_day_week: {rs.cron_day_week}")  # noqa

            if rs.job_id:
                # Add the jobs to the JOB table
                task_ids = self._insert_job(rs.job_id, rs.manifests)
                # Add the schedule_id and job_id to the repeated_schedule_job table
                self._insert_repeated_schedule_job_tables(schedule_id, task_ids)

            self._conn.commit()
        except (sqlite3.Error) as e:
            self._conn.rollback()
            logger.error(f"Transaction failed: {str(e)}")
            raise DispatcherException(f"Transaction failed: {str(e)}")

    def _insert_job(self, job_id: str, manifests: list[str]) -> list[int]:
        # Add the job to the job table
        if len(manifests) == 0:
            raise DispatcherException(
                "Error: At least one manifest is required for the schedule.  Manifest list is empty.")

        task_ids: list[int] = []

        for manifest in manifests:
            sql = ''' INSERT INTO job(job_id, manifest) VALUES(?,?); '''

            try:
                self._cursor.execute(sql, (job_id, manifest))
            except (sqlite3.Error) as e:
                logger.error(f"Error inserting job into JOB table: {e}")
                raise DispatcherException(f"Error inserting job into JOB table: {e}")

            task_id = self._cursor.lastrowid
            if not task_id:
                raise DispatcherException("No task_id was added to the JOB table.")

            logger.debug(f"Added job with id: {str(task_id)}.")
            task_ids.append(task_id)

        if not task_ids:
            raise DispatcherException("No new jobs were added to the JOB table.")

        return task_ids

    def _insert_single_schedule_jobs(self, schedule_id: int, task_ids: list[int]) -> None:
        # Add the priority, schedule_id, job_id to the join table
        for task_id in task_ids:
            priority = task_ids.index(task_id)
            logger.debug(
                f"Execute -> INSERT INTO single_schedule_job(priority, schedule_id, task_id) VALUES({priority}{schedule_id}{task_id})")

            sql = ''' INSERT INTO single_schedule_job(priority, schedule_id, task_id) VALUES(?,?,?); '''
            try:
                self._cursor.execute(sql, (priority, schedule_id, task_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting into single_schedule_job table: {e}")
            logger.debug(
                f"Inserted new tuple to single_schedule_job table with task_id: {str(task_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")

    def _insert_repeated_schedule_job_tables(self, schedule_id: int, task_ids: list[int]) -> None:
        # Add the schedule_id and job_id to the join table
        for task_id in task_ids:
            priority = task_ids.index(task_id)
            logger.debug(
                f"Execute -> INSERT INTO repeated_schedule_job(priority, schedule_id, task_id) VALUES({priority}{schedule_id}{task_id})")

            sql = ''' INSERT INTO repeated_schedule_job(priority, schedule_id, task_id) VALUES(?,?,?); '''
            try:
                self._cursor.execute(sql, (priority, schedule_id, task_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(
                    f"Error inserting new tuple to repeated_schedule_job table: {e}")

            logger.debug(
                f"Inserted new tuple to repeated_schedule_job table with task_id: {str(task_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")

    def _select_manifests_by_schedule_id(self, sql: str, schedule_id: int) -> list[str]:
        # Get the manifests from the join table
        logger.debug(f"Execute -> {sql} with schedule_id={schedule_id}")
        try:
            self._cursor.execute(sql, (schedule_id,))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error selecting schedule manifest from database: {e}")

        rows = self._cursor.fetchall()
        if len(rows) == 0:
            raise DispatcherException(f"No schedule manifest found with schedule_id: {schedule_id}")

        # cursor return [('MANIFEST1',), ('MANIFEST2',)].
        # Extract the strings from each tuple in the list
        manifests = [item[0] for item in rows]
        return manifests

    def _create_tables_if_not_exist(self) -> None:
        self._create_single_schedule_table()
        self._create_repeated_schedule_table()
        self._create_job_table()
        self._create_single_schedule_job_table()
        self._create_repeated_schedule_job_table()

    def _create_single_schedule_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id TEXT NOT NULL,
                                start_time TEXT NOT NULL,
                                end_time TEXT); '''
        self._conn.execute(sql)

    def _create_repeated_schedule_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id TEXT NOT NULL,
                                cron_duration TEXT NOT NULL,
                                cron_minutes TEXT NOT NULL,
                                cron_hours TEXT NOT NULL,
                                cron_day_month TEXT NOT NULL,
                                cron_month TEXT NOT NULL,
                                cron_day_week TEXT NOT NULL); '''
        self._conn.execute(sql)

    def _create_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS job(
                                task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                job_id TEXT NOT NULL,
                                manifest TEXT NOT NULL); '''
        self._conn.execute(sql)

    def _create_single_schedule_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule_job(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,                                
                                task_id INTEGER NOT NULL,
                                status TEXT,
                                FOREIGN KEY(task_id) REFERENCES JOB(task_id),
                                FOREIGN KEY(schedule_id) REFERENCES REPEATED_SCHEDULE(id),
                                PRIMARY KEY(schedule_id, task_id)); '''
        self._conn.execute(sql)

    def _create_repeated_schedule_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule_job(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,
                                task_id INTEGER NOT NULL,
                                status TEXT,
                                FOREIGN KEY(task_id) REFERENCES JOB(task_id),
                                FOREIGN KEY(schedule_id) REFERENCES REPEATED_SCHEDULE(id),
                                PRIMARY KEY(schedule_id, task_id)); '''
        self._conn.execute(sql)
