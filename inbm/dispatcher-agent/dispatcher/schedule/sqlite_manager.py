"""
    Creates a connection to a SQLite database. The connection is closed after the connection is established.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sqlite3
from typing import Any
from .schedules import SingleSchedule, RepeatedSchedule, Schedule
from ..dispatcher_exception import DispatcherException
from ..constants import UDM_DB_FILE

logger = logging.getLogger(__name__)


class SqliteManager:
    def __init__(self, db_file=UDM_DB_FILE) -> None:
        """Handles the connection to the SQLite database and all database operations.
        
        @param db_file: The path to the SQLite database file.  Defaults to UDM_DB_FILE.
        """
        self._db_file = db_file
        self._conn = None
        try:
            with sqlite3.connect(self._db_file) as conn:
                self._conn = conn        
        except sqlite3.Error as e:
           raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")
        
        self._cursor = self._conn.cursor()
        self._create_tables_if_not_exist() 
    

    def __del__(self) -> None:
        if self._cursor:
            self._cursor.close()
        if self._conn:
            self._conn.close()
            
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
                logger.error("Schedule type is neither a SingleSchedule nor a RepeatedSchedule object.")
        except (sqlite3.OperationalError, sqlite3.InternalError) as e:
            raise DispatcherException(f"Error connecting to Dispatcher Schedule database: {e}")
    
    def _create_single_schedule(self, ss: SingleSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(f"Execute -> INSERT INTO single_schedule_manifest(request_id, start_time, end_time) VALUES({ss.request_id}{ss.start_time}{ss.end_time})")

        sql = ''' INSERT INTO single_schedule(request_id, start_time, end_time)
                                VALUES(?,?,?); '''
        start_time = None if not ss.start_time else str(ss.start_time)
        end_time = None if not ss.end_time else str(ss.end_time)
        try:
            self._cursor.execute(sql, (ss.request_id, start_time, end_time))
            schedule_id = self._cursor.lastrowid
            if not schedule_id:
                raise DispatcherException("No schedule id was added to the single_schedule table.")
            
            logger.debug(f"Added schedule with id: {str(schedule_id)}, request_id: {ss.request_id}, start_time: {str(ss.start_time)}, end_time: {str(ss.end_time)}")
        
            # Add the manifests to the manifest table
            manifest_ids = self._insert_manifest_to_table(ss.manifests)
            
            # Add the schedule_id and manifest_id to the single_schedule_manifest table
            self._insert_single_schedule_manifest_tables(schedule_id, manifest_ids)         
            self._commit_transaction()
        except (sqlite3.DatabaseError) as e:
            self._rollback_transaction()
            raise DispatcherException(f"Transaction failed: {str(e)}")                       

    def _commit_transaction(self) -> None:
        if self._conn:
            self._conn.commit()
            
    def _execute_transaction(self, sql: str) -> None:
        if self._conn:
            self._conn.execute(sql)
            
    def _rollback_transaction(self) -> None:
        if self._conn:
            self._conn.rollback()

    def _create_repeated_schedule(self, rs: RepeatedSchedule) -> None:
        # Add the schedule to the single_schedule table
        logger.debug(f"Execute -> INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week) VALUES({rs.request_id}, {rs.cron_duration}, {rs.cron_minutes}, {rs.cron_hours}, {rs.cron_day_month}, {rs.cron_month}, {rs.cron_day_week})")

        sql = ''' INSERT INTO repeated_schedule(request_id, cron_duration, cron_minutes, cron_hours, cron_day_month, cron_month, cron_day_week)
                                VALUES(?,?,?,?,?,?,?); '''
        try:
            self._cursor.execute(sql, (rs.request_id, 
                                        rs.cron_duration, 
                                        rs.cron_minutes, 
                                        rs.cron_hours, 
                                        rs.cron_day_month, 
                                        rs.cron_month, 
                                        rs.cron_day_week))
            schedule_id = self._cursor.lastrowid
            if not schedule_id:
                raise DispatcherException("No schedule id was added to the repeated_schedule table.")
            
            logger.debug(f"Added repeated schedule with id: {str(schedule_id)}, request_id:{rs.request_id}, cron_duration: {rs.cron_duration}, cron_minutes: {rs.cron_minutes}, cron_hours: {rs.cron_hours}, cron_day_month: {rs.cron_day_month}, cron_month: {rs.cron_month}, cron_day_week: {rs.cron_day_week}") # noqa

            # Add the manifests to the manifest table
            manifest_ids = self._insert_manifest_to_table(rs.manifests)
            
            # Add the schedule_id and manifest_id to the repeated_schedule_manifest table
            self._insert_repeated_schedule_manifest_tables(schedule_id, manifest_ids)
            self._commit_transaction()
        except (sqlite3.DatabaseError) as e:
            self._rollback_transaction()
            raise DispatcherException(f"Transaction failed: {str(e)}")        
        
    def _insert_manifest_to_table(self, manifests: list[str]) -> list[int]:
        # Add the manifest to the manifest table
        if len(manifests) == 0:
            raise DispatcherException("Error: At least one manifest is required for the schedule.  Manifests list is empty.")

        manifest_ids: list[int] = []        
                
        for manifest in manifests:
            sql = ''' INSERT INTO manifest(manifest) VALUES(?); '''
            
            try: 
                self._cursor.execute(sql, (manifest,))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting manifests into MANIFEST table: {e}")

            manifest_id = self._cursor.lastrowid
            if not manifest_id:
                raise DispatcherException("No manifest id was added to the manifest table.")
           
            logger.debug(f"Added manifest with id: {str(manifest_id)}.")
            manifest_ids.append(manifest_id)
         
        if not manifest_ids:
            raise DispatcherException("No new manifests were added to the manifest table.")
        
        return manifest_ids    
       
    def _insert_single_schedule_manifest_tables(self, schedule_id: int, manifest_ids: list[int]) -> None:
        # Add the schedule_id and manifest_id to the join table
        for manifest_id in manifest_ids:
            priority = manifest_ids.index(manifest_id)
            logger.debug(f"Execute -> INSERT INTO single_schedule_manifest(priority, schedule_id, manifest_id) VALUES({priority}{schedule_id}{manifest_id})")

            sql = ''' INSERT INTO single_schedule_manifest(priority, schedule_id, manifest_id) VALUES(?,?,?); '''
            try:
                self._cursor.execute(sql, (priority, schedule_id, manifest_id))
            except (sqlite3.IntegrityError, sqlite3.InternalError, sqlite3.OperationalError) as e:
                raise DispatcherException(f"Error inserting into single_schedule_manifest table: {e}")
            logger.debug(f"Inserted new tuple to single_schedule_manifest table with manifest_id: {str(manifest_id)} to schedule with id: {str(schedule_id)}, with priority: {str(priority)}")
   
    def _insert_repeated_schedule_manifest_tables(self, schedule_id: int, manifest_ids: list[int]) -> None:
        # Add the schedule_id and manifest_id to the join table
        for manifest_id in manifest_ids:
            priority = manifest_ids.index(manifest_id)
            logger.debug(f"Execute -> INSERT INTO repeated_schedule_manifest(priority, schedule_id, manifest_id) VALUES({priority}{schedule_id}{manifest_id})")

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
        
        logger.debug(f"Execute -> SELECT -> single_schedule -> request_id={request_id}")
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
        
        logger.debug(f"Execute -> SELECT -> repeated_schedule -> request_id={request_id}")
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
        logger.debug(f"Execute -> {sql} with schedule_id={schedule_id}")
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
            logger.debug(f"Execute -> SELECT -> manifest -> id={row[2]}")
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
        self._execute_transaction(sql)
    
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
        self._execute_transaction(sql)
        
    def _create_manifest_table(self) -> None:      
        sql = ''' CREATE TABLE IF NOT EXISTS manifest(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                manifest TEXT); '''
        self._execute_transaction(sql)
        
    def _create_single_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS single_schedule_manifest(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL REFERENCES single_schedule(id),
                                manifest_id INTEGER NOT NULL REFERENCES manifest(id)); '''
        self._execute_transaction(sql)
        
    def _create_repeated_schedule_manifest_table(self) -> None:
        sql = ''' CREATE TABLE IF NOT EXISTS repeated_schedule_manifest(
                                priority INTEGER NOT NULL,
                                schedule_id INTEGER NOT NULL REFERENCES repeated_schedule(id),
                                manifest_id INTEGER NOT NULL REFERENCES manifest(id)); '''
        self._execute_transaction(sql)
