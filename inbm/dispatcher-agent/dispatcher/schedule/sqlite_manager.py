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
from typing import Any, List, Optional

from inbm_common_lib.utility import get_canonical_representation_of_path

from .schedules import SingleSchedule, RepeatedSchedule, Schedule
from ..dispatcher_exception import DispatcherException
from ..constants import SCHEDULER_DB_FILE

logger = logging.getLogger(__name__)


class SqliteManager:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance
    
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

        self._create_tables_if_not_exist()

    def close(self) -> None:
        """Close the connection to the SQLite database."""
        try:
            if self._conn:
                self._conn.close()
        except sqlite3.Error as e:
            logger.error(f"Error closing connection to Dispatcher Schedule database: {e}")

    def __del__(self) -> None:
        """Close the connection to the SQLite database."""
        self.close()

    def clear_database(self) -> None:
        """Clear the database of all data."""
        try:
            cursor = self._conn.cursor()
            cursor.execute('BEGIN')
            cursor.execute('DELETE FROM immediate_schedule_job;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='immediate_schedule_job';")
            cursor.execute('DELETE FROM single_schedule_job;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='single_schedule_job';")
            cursor.execute('DELETE FROM repeated_schedule_job;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='repeated_schedule_job';")
            cursor.execute('DELETE FROM immediate_schedule;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='immediate_schedule';")
            cursor.execute('DELETE FROM single_schedule;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='single_schedule';")
            cursor.execute('DELETE FROM repeated_schedule;')
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='repeated_schedule';")
            cursor.execute('DELETE FROM job;')
            cursor.execute('DELETE FROM sqlite_sequence WHERE name="job";')
            cursor.execute('COMMIT')
        except sqlite3.Error as e:
            self._rollback_transaction(str(e), "Error clearing database")
        finally:
            cursor.close()           

    def _create_db(self) -> None:
        # Create database file if not exist
        if self._db_file != ":memory:" and not os.path.exists(self._db_file):
            logger.info(f"Database file doesn't exist. Creating the file.")
            # Set permission of the file (rw for owner and group)
            mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP
            fd = os.open(self._db_file, os.O_CREAT | os.O_WRONLY, mode)
            os.close(fd)
        
    def _fetch_schedules(self, sql: str) -> list[Any]:
        try:
            cursor = self._conn.cursor()           
            cursor.execute(sql)
            return cursor.fetchall()
        finally:
            cursor.close()
             
    def get_any_started_schedule(self) -> Optional[Schedule]:
        sql = ''' SELECT 
            j.job_id,
            j.task_id,
            sj.schedule_id,
            sj.schedule_type,                    
            COALESCE(iss.request_id, sss.request_id, rss.request_id) AS request_id
        FROM 
            job j
        JOIN 
            (
                SELECT task_id, schedule_id, 'Immediate' AS schedule_type FROM immediate_schedule_job WHERE status = 'started'
                UNION ALL
                SELECT task_id, schedule_id, 'Single' AS schedule_type FROM single_schedule_job WHERE status = 'started'
                UNION ALL
                SELECT task_id, schedule_id, 'Repeated' AS schedule_type FROM repeated_schedule_job WHERE status = 'started'
            ) sj ON j.task_id = sj.task_id
        LEFT JOIN 
            immediate_schedule iss ON sj.schedule_id = iss.id AND sj.schedule_type = 'Immediate'
        LEFT JOIN 
            single_schedule sss ON sj.schedule_id = sss.id AND sj.schedule_type = 'Single'
        LEFT JOIN 
            repeated_schedule rss ON sj.schedule_id = rss.id AND sj.schedule_type = 'Repeated'
            '''
      
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql)
            row = cursor.fetchall()
            if len(row) > 1:
                raise DispatcherException("More than one schedule in 'started' state.")     
            if len(row) == 1:
                job_id = row[0][0]
                task_id = row[0][1]
                schedule_id = row[0][2]
                schedule_type = row[0][3]
                request_id = row[0][4]
                logger.debug(f"Schedule in 'STARTED' state has type={schedule_type}, jobID={job_id}, taskID={task_id}, scheduleID={schedule_id}, requestID={request_id}")

                if schedule_type == 'Immediate':
                    return SingleSchedule(request_id=request_id, job_id=job_id, task_id=task_id, schedule_id=schedule_id)
                elif schedule_type == 'Single':
                    return SingleSchedule(request_id=request_id, job_id=job_id, task_id=task_id, schedule_id=schedule_id, start_time=datetime.now())
                else:
                    return RepeatedSchedule(request_id=request_id, job_id=job_id, task_id=task_id, schedule_id=schedule_id)
            return None
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error in getting job in 'started' state: {e}")
        finally:
            cursor.close()
           
    def get_immediate_schedules_in_priority_order(self) -> List[SingleSchedule]:
        """
        Get all the immediate schedules.
        @return: List of Schedule object
        """
        
        sql = ''' SELECT isj.priority, isj.schedule_id, isj.task_id, j.job_id 
            FROM immediate_schedule_job isj  
            JOIN job j ON isj.task_id=j.task_id 
            WHERE isj.status IS NULL 
            ORDER BY priority ASC; '''            

        try:                       
            rows = self._fetch_schedules(sql)

            s: List[SingleSchedule] = []
            for row in rows:
                immediate_schedule = self._select_immediate_schedule_by_id(str(row[1]))
                immediate_schedule.manifests = [self._select_job_by_task_id(str(row[2]))]
                immediate_schedule.job_id = str(row[3])
                immediate_schedule.priority = row[0]
                immediate_schedule.task_id = row[2]
                s.append(immediate_schedule)
            return s    
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error in getting immediate schedules from database: {e}")
            
    def get_single_schedules_in_priority_order(self) -> List[SingleSchedule]:
        """
        Get all the SingleSchedule and arrange them by priority in ascending order.
        @return: List of SingleSchedule object by priority in ascending order
        """
        
        sql = ''' SELECT ssj.priority, ssj.schedule_id, ssj.task_id, j.job_id 
            FROM single_schedule_job ssj  
            JOIN job j ON ssj.task_id=j.task_id 
            WHERE ssj.status IS NULL 
            ORDER BY priority ASC; '''
            
        try:                       
            rows = self._fetch_schedules(sql)
            
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
                f"Error in getting single schedules from database: {e}")

    def get_repeated_schedules_in_priority_order(self) -> List[RepeatedSchedule]:
        """
        Get all the RepeatedSchedule and arrange them by priority in ascending order.
        @return: List of RepeatedSchedule object by priority in ascending order
        """
        
        sql = ''' SELECT rsj.priority, rsj.schedule_id, rsj.task_id, j.job_id 
        FROM repeated_schedule_job rsj 
        JOIN job j ON rsj.task_id=j.task_id 
        WHERE rsj.status IS NULL 
        ORDER BY priority ASC; '''
            
        try:
            rows = self._fetch_schedules(sql)
            
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
                f"Error in getting repeated schedules from database: {e}")

    def _fetch_one(self, sql: str, values: tuple) -> Any:
        try:
            cursor = self._conn.cursor()
            cursor.execute(sql, values)
            row = cursor.fetchone()
            return row
        finally:
            cursor.close()
            
    def _select_job_by_task_id(self, task_id: str) -> str:
        """Get the job stored in database by task id.
        @param id: row index
        @return: job
        """
        sql = ''' SELECT manifest FROM job WHERE rowid=?; '''
        row = self._fetch_one(sql, (task_id,))
            
        manifest = row[0]
        logger.debug(f"id={task_id}, manifest={manifest}")
        return manifest

    def _get_schedule_by_schedule_id(self, sql: str, schedule_id: str) -> Any:
        row = self._fetch_one(sql, (schedule_id,))
        if not row:
            raise DispatcherException(f"Unable to find the scheduleID: {schedule_id}.")
        return row
    
    def _select_immediate_schedule_by_id(self, schedule_id: str) -> SingleSchedule:
        """Get the immediate schedule stored in database by id.
        @param id: row index
        @return: Schedule object
        """ 
        sql = ''' SELECT request_id FROM immediate_schedule WHERE rowid=?; '''
        result = self._get_schedule_by_schedule_id(sql, schedule_id)
        request_id = result[0]

        logger.debug(
            f"schedule_id={schedule_id}, request_id={request_id}")
        return SingleSchedule(schedule_id=int(schedule_id), request_id=request_id)

    def _select_single_schedule_by_id(self, schedule_id: str) -> SingleSchedule:
        """Get the single schedule stored in database by id.
        @param id: row index
        @return: SingleSchedule object
        """ 
        sql = ''' SELECT request_id, start_time, end_time FROM single_schedule WHERE rowid=?; '''
        result = self._get_schedule_by_schedule_id(sql, schedule_id)
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
        result = self._get_schedule_by_schedule_id(sql, schedule_id)

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

        if schedule.task_id == -1:
            raise DispatcherException("Unable to update status in database as the task ID is not set.")

        sql = ""        
        if isinstance(schedule, SingleSchedule):
            if schedule.start_time:
                sql = ''' UPDATE single_schedule_job SET status = ? WHERE priority = ? AND schedule_id = ? AND task_id = ?; '''
            else:
                sql = ''' UPDATE immediate_schedule_job SET status = ? WHERE priority = ? AND schedule_id = ? AND task_id = ?; '''
        elif isinstance(schedule, RepeatedSchedule):
            sql = ''' UPDATE repeated_schedule_job SET status = ? WHERE priority = ? AND schedule_id = ? AND task_id = ?; '''
        else:
            raise DispatcherException("Unable to update status in database as the schedule type is not recognized.")
                  
        logger.debug(f"Update status in database for schedule: {schedule}")
        logger.debug(f"Update status in database to {status.upper()} with schedule_id={schedule.schedule_id}, task_id={schedule.task_id}")
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                sql, (status, schedule.priority, schedule.schedule_id, schedule.task_id))
            self._conn.commit()
            logger.debug(f"Status of JobID={schedule.job_id} updated in database to {status.upper()}.")
        except (sqlite3.Error) as e:
            raise DispatcherException(
                f"Error updating the schedule status in the Dispatcher Schedule database: {e}")
        finally:
            cursor.close()
         
    def create_schedule(self, schedule: Schedule) -> None:
        """
        Create a new schedule in the database.
        @param schedule: Schedule (Immediate), SingleSchedule or RepeatedSchedule object
        """
        try:
            if isinstance(schedule, RepeatedSchedule):
                logger.debug("Create REPEATED schedule")
                self._create_repeated_schedule(schedule)
            elif isinstance(schedule, SingleSchedule):                
                if schedule.start_time:
                    logger.debug("Create SINGLE schedule")
                    self._create_single_schedule(schedule)                  
                else: # Immediate Schedule
                    logger.debug("Create IMMEDIATE schedule")
                    self._create_immediate_schedule(schedule)
        except (sqlite3.Error) as e:
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")

    def _insert_schedule(self, sql: str, values: tuple) -> int:
        try:
            cursor = self._conn.cursor()
            cursor.execute('BEGIN')
            cursor.execute(sql, values)
            schedule_id = cursor.lastrowid            
            if not schedule_id:
                raise DispatcherException("No schedule id was added to the schedule table.")
            return schedule_id        
        except (sqlite3.Error) as e:
            cursor.execute('ROLLBACK')
            logger.error(f"Error inserting into schedule table:: {e}")
            raise DispatcherException(f"Error inserting into schedule table: {e}")
        finally:
            cursor.close()
        
    def _execute_sql_statement(self, sql: str, values: tuple, errMsg: str) -> None:       
        try:
            cursor = self._conn.cursor()
            cursor.execute(sql, values)
        except (sqlite3.Error) as e:
            self._rollback_transaction(str(e), errMsg)
        finally:
            cursor.close()
        
    def _rollback_transaction(self, e: str, errorMsg: str) -> None:
        try:
            cursor = self._conn.cursor()
            cursor.execute('ROLLBACK')
        finally:
            cursor.close()        
        logger.error(f"{errorMsg}: {e}")
        raise DispatcherException(f"{errorMsg}: {e}")
        
    def _create_immediate_schedule(self, s: Schedule) -> None:
        # Add the schedule to the immediate_schedule table
        logger.debug("Create IMMEDIATE schedule")
        logger.debug(
            f"Execute -> INSERT INTO immediate_schedule(request_id) VALUES({s.request_id})")

        sql = ''' INSERT INTO immediate_schedule(request_id) VALUES(?); '''
        try:
            schedule_id = self._insert_schedule(sql, (s.request_id,))

            logger.debug(
                f"Added schedule with id: {str(schedule_id)}, request_id: {s.request_id}")

            if s.job_id:
                # Add the jobs to the job table
                task_ids = self._insert_job(s.job_id, s.manifests)
                # Add the schedule_id and job_id to the immediate_schedule_job table
                self._insert_immediate_schedule_jobs(schedule_id, task_ids)
            
            self._conn.commit()
        except (sqlite3.Error) as e:
            self._rollback_transaction(str(e), "Transaction failed to create immediate schedule")

    def _create_single_schedule(self, ss: SingleSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(
            f"Execute -> INSERT INTO single_schedule(request_id, start_time, end_time) VALUES({ss.request_id}{ss.start_time}{ss.end_time})")

        sql = ''' INSERT INTO single_schedule(request_id, start_time, end_time)
                                VALUES(?,?,?); '''
        start_time = None if not ss.start_time else str(ss.start_time)
        end_time = None if not ss.end_time else str(ss.end_time)
        try:
            schedule_id = self._insert_schedule(sql, (ss.request_id, start_time, end_time))
            
            logger.debug(
                f"Added schedule with id: {str(schedule_id)}, request_id: {ss.request_id}, start_time: {start_time}, end_time: {ss.end_time}")

            if ss.job_id:
                # Add the jobs to the job table
                task_ids = self._insert_job(ss.job_id, ss.manifests)
                # Add the schedule_id and job_id to the single_schedule_job table
                self._insert_single_schedule_jobs(schedule_id, task_ids)

            self._conn.commit()
        except (sqlite3.Error) as e:
            self._rollback_transaction(str(e), "Transaction failed to create single schedule")

    def _create_repeated_schedule(self, rs: RepeatedSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(
            f"Execute -> INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week) VALUES({rs.request_id}, {rs.cron_duration}, {rs.cron_minutes}, {rs.cron_hours}, {rs.cron_day_month}, {rs.cron_month}, {rs.cron_day_week})")

        sql = ''' INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week)
                                VALUES(?,?,?,?,?,?,?); '''
        try:
            schedule_id = self._insert_schedule(sql, (rs.request_id,
                                                        rs.cron_duration,
                                                        rs.cron_minutes,
                                                        rs.cron_hours,
                                                        rs.cron_day_month,
                                                        rs.cron_month,
                                                        rs.cron_day_week,))
            
            logger.debug(f"Added repeated schedule with id: {str(schedule_id)}, request_id:{rs.request_id}, job_id:{rs.job_id}, cron_duration: {rs.cron_duration}, cron_minutes: {rs.cron_minutes}, cron_hours: {rs.cron_hours}, cron_day_month: {rs.cron_day_month}, cron_month: {rs.cron_month}, cron_day_week: {rs.cron_day_week}")  # noqa

            if rs.job_id:
                # Add the jobs to the JOB table
                task_ids = self._insert_job(rs.job_id, rs.manifests)
                # Add the schedule_id and job_id to the repeated_schedule_job table
                self._insert_repeated_schedule_job_tables(schedule_id, task_ids)

            self._conn.commit()
        except (sqlite3.Error) as e:
            self._rollback_transaction(str(e), "Transaction failed to create repeated schedule")

    def _insert_job(self, job_id: str, manifests: list[str]) -> list[int]:
        # Add the job to the job table
        if len(manifests) == 0:
            raise DispatcherException(
                "Error: At least one manifest is required for the schedule.  Manifest list is empty.")

        task_ids: list[int] = []

        for manifest in manifests:
            logger.debug(
                f"Execute -> INSERT INTO job(job_id, manifest) VALUES({job_id}{manifest})")

            sql = ''' INSERT INTO job(job_id, manifest) VALUES(?,?); '''

            try: 
                cursor = self._conn.cursor()       
                cursor.execute(sql, (job_id, manifest))
            except (sqlite3.Error) as e:
                logger.error(f"Error inserting job into JOB table: {e}")
                raise DispatcherException(f"Error inserting job into JOB table: {e}")
            finally:
                cursor.close()

            task_id = cursor.lastrowid
            if not task_id:
                raise DispatcherException("No task_id was added to the JOB table.")

            logger.debug(f"Added job with id: {str(task_id)}.")
            task_ids.append(task_id)

        if not task_ids:
            raise DispatcherException("No new jobs were added to the JOB table.")

        return task_ids

    def _insert_immediate_schedule_jobs(self, schedule_id: int, task_ids: list[int]) -> None:
        # Add the priority, schedule_id, job_id to the join table
        for task_id in task_ids:
            priority = task_ids.index(task_id)
            logger.debug(
                f"Execute -> INSERT INTO immediate_schedule_job(priority, schedule_id, task_id) VALUES({priority}{schedule_id}{task_id})")

            sql = ''' INSERT INTO immediate_schedule_job(priority, schedule_id, task_id) VALUES(?,?,?); '''
            try:  
                cursor = self._conn.cursor()     
                cursor.execute(sql, (priority, schedule_id, task_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting into immediate_schedule_job table: {e}")
            finally:
                cursor.close()
            logger.debug(
                f"Inserted new tuple to immediate_schedule_job table with task_id: {str(task_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")

    def _insert_single_schedule_jobs(self, schedule_id: int, task_ids: list[int]) -> None:
        # Add the priority, schedule_id, job_id to the join table
        for task_id in task_ids:
            priority = task_ids.index(task_id)
            logger.debug(
                f"Execute -> INSERT INTO single_schedule_job(priority, schedule_id, task_id) VALUES({priority}{schedule_id}{task_id})")

            sql = ''' INSERT INTO single_schedule_job(priority, schedule_id, task_id) VALUES(?,?,?); '''
            try:
                cursor = self._conn.cursor()
                cursor.execute(sql, (priority, schedule_id, task_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting into single_schedule_job table: {e}")
            finally:
                cursor.close()
                
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
                cursor = self._conn.cursor()
                cursor.execute(sql, (priority, schedule_id, task_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(
                    f"Error inserting new tuple to repeated_schedule_job table: {e}")
            finally:
                cursor.close()

            logger.debug(
                f"Inserted new tuple to repeated_schedule_job table with task_id: {str(task_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")

    def _create_tables_if_not_exist(self) -> None:
        self._create_immediate_schedule_table()
        self._create_single_schedule_table()
        self._create_repeated_schedule_table()
        self._create_job_table()
        self._create_immediate_schedule_job_table()
        self._create_single_schedule_job_table()
        self._create_repeated_schedule_job_table()        

    def _create_immediate_schedule_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS immediate_schedule(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id TEXT NOT NULL); '''
        self._execute_sql_statement(sql, (), "Error creating immediate_schedule table")
        
    def _create_single_schedule_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id TEXT NOT NULL,
                                start_time TEXT NOT NULL,
                                end_time TEXT); '''
        self._execute_sql_statement(sql, (), "Error creating single_schedule table")

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
        self._execute_sql_statement(sql, (), "Error creating repeated_schedule table")

    def _create_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS job(
                                task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                job_id TEXT NOT NULL,
                                manifest TEXT NOT NULL); '''
        self._execute_sql_statement(sql, (), "Error creating job table")

    def _create_immediate_schedule_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS immediate_schedule_job(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,                                
                                task_id INTEGER NOT NULL,
                                status TEXT,
                                FOREIGN KEY(task_id) REFERENCES JOB(task_id),
                                FOREIGN KEY(schedule_id) REFERENCES IMMEDIATE_SCHEDULE(id),
                                PRIMARY KEY(schedule_id, task_id)); '''
        self._execute_sql_statement(sql, (), "Error creating immediate_schedule_job table")
        
    def _create_single_schedule_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule_job(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,                                
                                task_id INTEGER NOT NULL,
                                status TEXT,
                                FOREIGN KEY(task_id) REFERENCES JOB(task_id),
                                FOREIGN KEY(schedule_id) REFERENCES SINGLE_SCHEDULE(id),
                                PRIMARY KEY(schedule_id, task_id)); '''
        self._execute_sql_statement(sql, (), "Error creating single_schedule_job table")

    def _create_repeated_schedule_job_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule_job(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,
                                task_id INTEGER NOT NULL,
                                status TEXT,
                                FOREIGN KEY(task_id) REFERENCES JOB(task_id),
                                FOREIGN KEY(schedule_id) REFERENCES REPEATED_SCHEDULE(id),
                                PRIMARY KEY(schedule_id, task_id)); '''
        self._execute_sql_statement(sql, (), "Error creating repeated_schedule_job table")
