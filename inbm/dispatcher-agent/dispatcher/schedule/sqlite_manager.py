"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
from typing import Union
from .schedules import SingleSchedule, RepeatedSchedule
from ..dispatcher_exception import DispatcherException
from ..constants import UDM_DB_FILE

logger = logging.getLogger(__name__)


class SqliteManager:
    def __init__(self, db_file=UDM_DB_FILE) -> None:
        self._db_file = db_file
        self._conn: sqlite3.Connection = sqlite3.connect(self._db_file)
        self._create_tables_if_not_exist()

    def create_schedule(self, schedule: Union[SingleSchedule, RepeatedSchedule]) -> None:
        """
        Create a new schedule task in the database.
        @param schedule: SingleSchedule or RepeatedSchedule object
        """
        try:
            if isinstance(schedule, SingleSchedule):
                self._create_single_schedule(schedule, self.conn)
            elif isinstance(schedule, RepeatedSchedule):
                self._create_repeated_schedule(schedule, self.conn)
            else:
                print("Schedule type is neither a SingleSchedule nor a RepeatedSchedule object.")
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")
        finally:
            if self._conn:
                self._conn.close()
    
    def _create_single_schedule(self, ss: SingleSchedule, conn: sqlite3.Connection) -> None:
        # Creating the table
        cur = self._conn.cursor()

        # Add the schedule to the single_schedule table
        sql = ''' INSERT INTO single_schedule(request_id, start_time, end_time)
                                VALUES(?,?,?); '''
        try:
            cur.execute(sql, (str(ss.request_id), 
                            str(ss.start_time), 
                            str(ss.end_time)))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error adding single schedule to database: {e}")
        
        schedule_id = cur.lastrowid
        logger.debug(f"Added schedule with id: {str(schedule_id)}, request_id: {ss.request_id}, start_time: {str(ss.start_time)}, end_time: {str(ss.end_time)}")
        
        # Add the manifests to the manifest table
        manifest_ids = self._add_manifest_to_table(cur, ss.manifests)
        
        # Add the schedule_id and manifest_id to the single_schedule_manifest table
        self._join_schedule_manifest_tables(cur, "single_schedule_manifest", schedule_id, manifest_ids)
          
        cur.commit()

    def _create_repeated_schedule(self, rs: RepeatedSchedule, conn: sqlite3.Connection) -> None:
        # Creating the table
        cur = self._conn.cursor()

        # Add the schedule to the single_schedule table
        sql = ''' INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week)
                                VALUES(?,?,?,?,?,?,?); '''
        try:
            cur.execute(sql, (str(rs.request_id), 
                            str(rs.cron_duration), 
                            str(rs.cron_minutes), 
                            str(rs.cron_hours), 
                            str(rs.cron_day_month), 
                            str(rs.cron_month), 
                            str(rs.cron_day_week)))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error adding repeated schedule to database: {e}")
        
        schedule_id = cur.lastrowid
        logger.debug(f"Added repeated schedule with id: {str(schedule_id)}, request_id:{rs.request_id}, cron_duration: {rs.cron_duration}, cron_minutes: {rs.cron_minutes}, cron_hours: {rs.cron_hours}, cron_day_month: {rs.cron_day_month}, cron_month: {rs.cron_month}, cron_day_week: {rs.cron_day_week}")
        
        # Add the manifests to the manifest table
        manifest_ids = self._add_manifest_to_table(cur, rs.manifests)
        
        # Add the schedule_id and manifest_id to the repeated_schedule_manifest table
        self._join_schedule_manifest_tables(cur, "repeated_schedule_manifest", schedule_id, manifest_ids)
          
        cur.commit()
        
    def _add_manifest_to_table(self, cur: sqlite3.Cursor, manifests: list[str]) -> list[int]:
        # Add the manifest to the manifest table
        manifest_ids: list[int] = []
        for manifest in manifests:
            sql = ''' INSERT INTO manifest(manifest) VALUES(?); '''
            cur.execute(sql, manifest)
            manifest_id = cur.lastrowid
            logger.debug(f"Added manifest with id: {str(manifest_id)}.")
            manifest_ids.append(manifest_id)
        return manifest_ids
    
    def _join_schedule_manifest_tables(self, cur: sqlite3.Cursor, table_name: str, schedule_id: int, manifest_ids: list[int]) -> None:
        # Add the schedule_id and manifest_id to the join table
        for manifest_id in manifest_ids:
            priority = manifest_ids.index(manifest_id)
            sql = ''' INSERT INTO ?(priority, schedule_id, manifest_id) VALUES(?,?,?); '''
            cur.execute(sql, table_name, priority, schedule_id, manifest_id)
            logger.debug(f"Added to join table {table_name} with manifest_id: {str(manifest_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")
            
    def _create_tables_if_not_exist(self) -> None:
        self._create_single_schedule_table()
        self._create_repeated_schedule_table()
        self._create_manifest_table()
        self._create_single_schedule_manfiest_table()
        self._create_repeated_schedule_manifest_table()
    
    def _create_single_schedule_table(self) -> None:      
        sql = ''' CREATE TABLE single_schedule IF NOT EXISTS (
                                id integer INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id text,
                                start_time text,
                                end_time text
                            ); '''
        self._conn.execute(sql)
    
    def _create_repeated_schedule_table(self) -> None:      
        sql = ''' CREATE TABLE repeated_schedule IF NOT EXISTS (
                                id integer INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_id text,
                                cron_duration text,
                                cron_minutes text,
                                cron_hours text,
                                cron_day_month text,
                                cron_month text,
                                cron_day_week text); '''
        self._conn.execute(sql)
        
    def _create_manifest_table(self) -> None:      
        sql = ''' CREATE TABLE manifest IF NOT EXISTS (
                                id integer INTEGER PRIMARY KEY AUTOINCREMENT,
                                manifest text); '''
        self._conn.execute(sql)
        
    def _create_single_schedule_manfiest_table(self) -> None:
        sql = ''' CREATE TABLE single_schedule_manifest IF NOT EXISTS (
                                id integer INTEGER PRIMARY KEY AUTOINCREMENT,
                                schedule_id integer,
                                manifest_id integer); '''
        self._conn.execute(sql)
        
    def _create_repeated_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE repeated_schedule_manifest IF NOT EXISTS (
                                id integer INTEGER PRIMARY KEY AUTOINCREMENT,
                                schedule_id integer,
                                manifest_id integer); '''
        self._conn.execute(sql)
