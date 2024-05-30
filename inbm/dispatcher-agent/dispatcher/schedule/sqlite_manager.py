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
        self._cursor = self._conn.cursor()

    def __del__(self) -> None:
        if self._conn:
            self._conn.close()
            
    def create_schedule(self, schedule: Union[SingleSchedule, RepeatedSchedule]) -> None:
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
                print("Schedule type is neither a SingleSchedule nor a RepeatedSchedule object.")
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")
    
    def _create_single_schedule(self, ss: SingleSchedule) -> None:
        # Add the schedule to the single_schedule table
        sql = ''' INSERT INTO single_schedule(request_id, start_time, end_time)
                                VALUES(?,?,?); '''
        try:
            self._cursor.execute(sql, (str(ss.request_id), 
                            str(ss.start_time), 
                            str(ss.end_time)))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error adding single schedule to database: {e}")
        
        schedule_id = self._cursor.lastrowid
        if not schedule_id:
            raise DispatcherException("No schedule id was added to the single_schedule table.")
        logger.debug(f"Added schedule with id: {str(schedule_id)}, request_id: {ss.request_id}, start_time: {str(ss.start_time)}, end_time: {str(ss.end_time)}")
        
        # Add the manifests to the manifest table
        manifest_ids = self._insert_manifest_to_table(ss.manifests)
        
        # Add the schedule_id and manifest_id to the single_schedule_manifest table
        self._insert_single_schedule_manifest_tables(schedule_id, manifest_ids)         
        self._conn.commit()

    def _create_repeated_schedule(self, rs: RepeatedSchedule) -> None:
        # Add the schedule to the single_schedule table
        sql = ''' INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week)
                                VALUES(?,?,?,?,?,?,?); '''
        try:
            self._cursor.execute(sql, (str(rs.request_id), 
                            str(rs.cron_duration), 
                            str(rs.cron_minutes), 
                            str(rs.cron_hours), 
                            str(rs.cron_day_month), 
                            str(rs.cron_month), 
                            str(rs.cron_day_week)))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error adding repeated schedule to database: {e}")
        
        schedule_id = self._cursor.lastrowid
        if not schedule_id:
            raise DispatcherException("No schedule id was added to the repeated_schedule table.")
        logger.debug(f"Added repeated schedule with id: {str(schedule_id)}, request_id:{rs.request_id}, cron_duration: {rs.cron_duration}, cron_minutes: {rs.cron_minutes}, cron_hours: {rs.cron_hours}, cron_day_month: {rs.cron_day_month}, cron_month: {rs.cron_month}, cron_day_week: {rs.cron_day_week}") # noqa
        
        # Add the manifests to the manifest table
        manifest_ids = self._insert_manifest_to_table(cur, rs.manifests)
           
        # Add the schedule_id and manifest_id to the repeated_schedule_manifest table
        self._insert_repeated_schedule_manifest_tables(cur, schedule_id, manifest_ids)
        self._conn.commit()
        
    def _insert_manifest_to_table(self, manifests: list[str]) -> list[int]:
        # Add the manifest to the manifest table
        manifest_ids: list[int] = []
        
        for manifest in manifests:
            sql = ''' INSERT INTO manifest(manifest) VALUES(?); '''
            try: 
                self._cursor.execute(sql, (manifest,))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting manifests into MANIFEST table: {e}")

            manifest_id = self._cursor.lastrowid
            if not manifest_id:
                raise DispatcherException("No new manifest was added to the manifest table.")
            
            logger.debug(f"Added manifest with id: {str(manifest_id)}.")
            manifest_ids.append(manifest_id)
         
        if not manifest_ids:
            raise DispatcherException("No new manifests were added to the manifest table.")
        
        return manifest_ids    
       
    def _insert_single_schedule_manifest_tables(self, schedule_id: int, manifest_ids: list[int]) -> None:
        # Add the schedule_id and manifest_id to the join table
        for manifest_id in manifest_ids:
            priority = manifest_ids.index(manifest_id)
            sql = ''' INSERT INTO single_schedule_manifest(priority, schedule_id, manifest_id) VALUES(?,?,?); '''
            try:
                self._cursor.execute(sql, (priority, schedule_id, manifest_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"error inserting into singel_schedule_manifest table: {e}")
            logger.debug(f"Inserted new tuple to single_schedule_manifest table with manifest_id: {str(manifest_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")
   
    def _insert_repeated_schedule_manifest_tables(self, schedule_id: int, manifest_ids: list[int]) -> None:
        # Add the schedule_id and manifest_id to the join table
        for manifest_id in manifest_ids:
            priority = manifest_ids.index(manifest_id)
            sql = ''' INSERT INTO repeated_schedule_manifest(priority, schedule_id, manifest_id) VALUES(?,?,?); '''
            try:
                self._cursor.execute(sql, (priority, schedule_id, manifest_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting new tuple to repeated_schedule_manifest table: {e}")

            logger.debug(f"Inserted new tuple to repeated_schedule_manifest table with manifest_id: {str(manifest_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")
 
    def select_single_schedule_by_request_id(self, request_id: str) -> list[SingleSchedule]:
        sql = ''' SELECT * FROM single_schedule WHERE request_id = ?'; '''
        try:
            self._cursor.execute(sql)
            self._cursor.row_factory = None
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error selecting single schedule from database: {e}")
        
        rows = self._cursor.fetchall()
        self._conn.commit()
        ss: SingleSchedule = []
        for row in rows:            
            ss.append(SingleSchedule(request_id=request_id, start_time=row))
        return ss
        
    def _create_tables_if_not_exist(self) -> None:
        self._create_single_schedule_table()
        self._create_repeated_schedule_table()
        self._create_manifest_table()
        self._create_single_schedule_manifest_table()
        self._create_repeated_schedule_manifest_table()
    
    def _create_single_schedule_table(self) -> None:      
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule(
                                request_id text,
                                start_time text,
                                end_time text
                            ); '''
        self._conn.execute(sql)
    
    def _create_repeated_schedule_table(self) -> None:      
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule(
                                request_id text,
                                cron_duration text,
                                cron_minutes text,
                                cron_hours text,
                                cron_day_month text,
                                cron_month text,
                                cron_day_week text); '''
        self._conn.execute(sql)
        
    def _create_manifest_table(self) -> None:      
        sql = ''' CREATE TABLE IF NOT EXISTS manifest(
                                manifest text); '''
        self._conn.execute(sql)
        
    def _create_single_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule_manifest(
                                priority INTEGER,
                                schedule_id INTEGER,
                                manifest_id INTEGER); '''
        self._conn.execute(sql)
        
    def _create_repeated_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule_manifest(
                                priority INTEGER,
                                schedule_id INTEGER,
                                manifest_id INTEGER); '''
        self._conn.execute(sql)
