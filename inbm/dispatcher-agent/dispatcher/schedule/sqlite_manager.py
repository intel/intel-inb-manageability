"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
from typing import Union, Any
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
        manifest_ids = self._insert_manifest_to_table(rs.manifests)
           
        # Add the schedule_id and manifest_id to the repeated_schedule_manifest table
        self._insert_repeated_schedule_manifest_tables(schedule_id, manifest_ids)
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
        """Create a list of SingleSchedule objects from the database matching the request_id
        @param request_id: request ID to match in the database
        @return: list of SingleSchedule objects
        """
        
        sql = ''' SELECT * FROM single_schedule WHERE request_id = ? '''
        try:
            self._cursor.execute(sql, (request_id,))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error selecting single schedule from database: {e}")
        
        ss_rows = self._cursor.fetchall()
        if len(ss_rows) == 0:
            raise DispatcherException(f"No single schedule found with request_id: {request_id}")
                       
        ss: list[SingleSchedule] = []
        for row in ss_rows:
            # Get the ids for the manifests matching the schedules from the join table (single_schedule_manifest)
            sql = ''' SELECT * FROM single_schedule_manifest WHERE schedule_id = ? '''
            ssm_rows = self._select_manifest_ids_by_schedule_id(sql, row[0])            
            manifests = self._select_manifests_by_schedule_id(ssm_rows)      
            
            ss.append(SingleSchedule(id=row[0], request_id=row[1], start_time=row[2], end_time=row[3], manifests=manifests))
        return ss
    
    def select_repeated_schedule_by_request_id(self, request_id: str) -> list[RepeatedSchedule]:
        """Create a list of RepeatedSchedule objects from the database matching the request_id
        @param request_id: request ID to match in the database
        @return: list of RepeatedSchedule objects
        """
        
        sql = ''' SELECT * FROM repeated_schedule WHERE request_id = ? '''
        try:
            self._cursor.execute(sql, (request_id,))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error selecting repeated schedule from database: {e}")
        
        rs_rows = self._cursor.fetchall()
        if len(rs_rows) == 0:
            raise DispatcherException(f"No repeated schedule found with request_id: {request_id}")
        
        rs: list[RepeatedSchedule] = []
        for row in rs_rows:
            sql = ''' SELECT * FROM repeated_schedule_manifest WHERE schedule_id = ? '''
            rsm_rows = self._select_manifest_ids_by_schedule_id(sql, row[0])            
            manifests = self._select_manifests_by_schedule_id(rsm_rows)                
            rs.append(RepeatedSchedule(id=row[0], request_id=row[1], cron_duration=row[2], cron_minutes=row[3], 
                                       cron_hours=row[4], cron_day_month=row[5], cron_month=row[6], cron_day_week=row[7],
                                       manifests=manifests))
        return rs
        
    def _select_manifest_ids_by_schedule_id(self, sql: str, schedule_id: int) -> list[int]:
        # Get the manifest_ids from the join table
        try:
            self._cursor.execute(sql, (schedule_id,))
        except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
            raise DispatcherException(f"Error selecting schedule manifest from database: {e}")
        
        rows = self._cursor.fetchall()
        if len(rows) == 0:
            raise DispatcherException(f"No schedule manifest found with schedule_id: {schedule_id}")
        return rows
    
    def _select_manifests_by_schedule_id(self, schedule_manifest_rows: list[Any]) -> list[str]:
        # Get the manifests using the manifest_ids from the join table
        manifests: list[str] = []
        for row in schedule_manifest_rows:
            # Get the manifests using the manifest_ids from the join table
            sql = ''' SELECT * FROM manifest WHERE id = ? '''
            try:
                self._cursor.execute(sql, (row[2],))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error selecting manifest from database: {e}")
            
            manifest_row = self._cursor.fetchone()
            if not manifest_row:
                raise DispatcherException(f"No manifest found with id: {manifest_row[2]}")
            manifests.append(manifest_row[1])
        return manifests  
                 
    def _create_tables_if_not_exist(self) -> None:
        self._create_single_schedule_table()
        self._create_repeated_schedule_table()
        self._create_manifest_table()
        self._create_single_schedule_manifest_table()
        self._create_repeated_schedule_manifest_table()
    
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
                                request_id TEXT,
                                cron_duration TEXT,
                                cron_minutes TEXT,
                                cron_hours TEXT,
                                cron_day_month TEXT,
                                cron_month TEXT,
                                cron_day_week TEXT); '''
        self._conn.execute(sql)
        
    def _create_manifest_table(self) -> None:      
        sql = ''' CREATE TABLE IF NOT EXISTS manifest(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                manifest TEXT); '''
        self._conn.execute(sql)
        
    def _create_single_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule_manifest(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,
                                manifest_id INTEGER NOT NULL); '''
        self._conn.execute(sql)
        
    def _create_repeated_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule_manifest(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL,
                                manifest_id INTEGER NOT NULL); '''
        self._conn.execute(sql)
