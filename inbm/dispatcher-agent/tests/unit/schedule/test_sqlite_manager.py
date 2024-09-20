import sqlite3
from unittest.mock import MagicMock, patch
import pytest

from datetime import datetime

from dispatcher.schedule.sqlite_manager import SqliteManager
from dispatcher.schedule.schedules import Schedule, SingleSchedule, RepeatedSchedule
from dispatcher.dispatcher_exception import DispatcherException

REQUEST_ID = "4324a262-b7d1-46a7-b8cc-84d934c3983f"
JOB_ID = "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"

@pytest.fixture
def db_connection():
    # Setup: create a new in-memory database connection using the custom class
    db_conn = SqliteManager(":memory:")
    
    # Yield the custom database connection to the test
    yield db_conn

    # Teardown: close the connection after the test is done
    db_conn.close()

def test_rollback_called_on_insert_immediate_scheduled_job(db_connection: SqliteManager,):
    s = SingleSchedule(request_id=REQUEST_ID,
                 job_id=JOB_ID,
                 manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()
  
    with patch.object(db_connection, '_insert_job', side_effect=sqlite3.Error("Mocked exception")):
        with patch.object(db_connection, '_rollback_transaction', new_callable=MagicMock()) as mock_rollback:
            db_connection.create_schedule(s)
            mock_rollback.assert_called()
            
def test_rollback_called_on_insert_single_scheduled_job(db_connection: SqliteManager,):
    ss = SingleSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         end_time=datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()
  
    with patch.object(db_connection, '_insert_job', side_effect=sqlite3.Error("Mocked exception")):
        with patch.object(db_connection, '_rollback_transaction', new_callable=MagicMock()) as mock_rollback:
            db_connection.create_schedule(ss)
            mock_rollback.assert_called()

def test_rollback_called_on_insert_repeated_scheduled_job(db_connection: SqliteManager,):
    rs = RepeatedSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         cron_duration="P7D", cron_minutes="0", 
                         cron_hours="0", cron_day_month="*",
                         cron_month="*", cron_day_week="1-5",
                         manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()
  
    with patch.object(db_connection, '_insert_job', side_effect=sqlite3.Error("Mocked exception")):
        with patch.object(db_connection, '_rollback_transaction', new_callable=MagicMock()) as mock_rollback:
            db_connection.create_schedule(rs)
            mock_rollback.assert_called()

def test_raises_sqlite_exception_on_get_immediate_schedules(db_connection: SqliteManager,):
    with patch.object(db_connection, '_fetch_schedules', side_effect=sqlite3.Error("Mocked database error")):
        with pytest.raises(DispatcherException) as excinfo:
            schedules = db_connection.get_immediate_schedules_in_priority_order()
        assert "Error in getting immediate schedules from database: Mocked database error" in str(excinfo.value)

def test_raises_sqlite_exception_on_get_single_schedules(db_connection: SqliteManager,):
    with patch.object(db_connection, '_fetch_schedules', side_effect=sqlite3.Error("Mocked database error")):
        with pytest.raises(DispatcherException) as excinfo:
            schedules = db_connection.get_single_schedules_in_priority_order()
        assert "Error in getting single schedules from database: Mocked database error" in str(excinfo.value)

def test_raises_sqlite_exception_on_get_repeated_schedules(db_connection: SqliteManager,):
    with patch.object(db_connection, '_fetch_schedules', side_effect=sqlite3.Error("Mocked database error")):
        with pytest.raises(DispatcherException) as excinfo:
            schedules = db_connection.get_repeated_schedules_in_priority_order()
        assert "Error in getting repeated schedules from database: Mocked database error" in str(excinfo.value)

@pytest.mark.parametrize("job_state, expected_job_id", [
    # Success - no started jobs
    ("scheduled", ""),
    # Success - one started job
    ("started", JOB_ID), 
 ])

def test_return_no_job_id_for_immediate_scheduled_job(db_connection: SqliteManager, job_state, expected_job_id):
    s = SingleSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,                         
                         manifests=["MANIFEST1"])
    db_connection.clear_database()
    
    db_connection.create_schedule(s)
    s.task_id = 1
    s.schedule_id = 1
 
    db_connection.update_status(s, job_state)
    job_id, task_id = db_connection.get_ids_of_started_job()
    
    assert job_id == expected_job_id

def test_update_single_schedule_status_to_scheduled(db_connection: SqliteManager):
    ss = SingleSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         end_time=datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()

    db_connection.create_schedule(ss)
    # SQL call only gets results that don't have a status.  
    results = db_connection.get_single_schedules_in_priority_order()
    assert len(results) == 2
    db_connection.update_status(results[0], "scheduled")
    db_connection.update_status(results[1], "scheduled")
    results = db_connection.get_single_schedules_in_priority_order()
    assert len(results) == 0
    
def test_update_repeated_schedule_statu_to_scheduled(db_connection: SqliteManager):
    rs = RepeatedSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         cron_duration="P7D", cron_minutes="0", 
                         cron_hours="0", cron_day_month="*",
                         cron_month="*", cron_day_week="1-5",
                         manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()

    db_connection.create_schedule(rs)
    # SQL call only gets results that don't have a status.  
    results = db_connection.get_repeated_schedules_in_priority_order()
    assert len(results) == 2
    db_connection.update_status(results[0], "scheduled")
    db_connection.update_status(results[1], "scheduled")
    results = db_connection.get_repeated_schedules_in_priority_order()
    assert len(results) == 0

def test_update_immediate_schedule_status_to_scheduled(db_connection: SqliteManager):
    s = SingleSchedule(request_id=REQUEST_ID,
                 job_id=JOB_ID,
                 manifests=["MANIFEST1", "MANIFEST2"])
    db_connection.clear_database()

    db_connection.create_schedule(s)
    # SQL call only gets results that don't have a status.  
    results = db_connection.get_immediate_schedules_in_priority_order()
    assert len(results) == 2
    db_connection.update_status(results[0], "scheduled")
    db_connection.update_status(results[1], "scheduled")
    results = db_connection.get_immediate_schedules_in_priority_order()
    assert len(results) == 0
    
@pytest.mark.parametrize("start_time, end_time, manifests, expected_exception, exception_text", [
    # Success
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     ["MANIFEST1", "MANIFEST2"], None, None),
    # Success - no end time
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     None, 
     ["MANIFEST1", "MANIFEST2"], None, None),
    # Fail - no manifests
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
    datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
    [], DispatcherException, "Error: At least one manifest is required for the schedule.  Manifest list is empty."),
])

def test_create_single_schedule_with_various_parameters(db_connection: SqliteManager, 
                                                start_time, end_time, manifests, 
                                                expected_exception, exception_text):
    ss = SingleSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         start_time=start_time,
                         end_time=end_time,
                         manifests=manifests)
    db_connection.clear_database()
    if expected_exception:
        with pytest.raises(expected_exception) as excinfo:
            db_connection.create_schedule(ss)
        assert exception_text in str(excinfo.value)
    else:
        db_connection.create_schedule(ss)
        results = db_connection.get_single_schedules_in_priority_order()
        assert len(results) == 2
        for result in results:
            assert result.request_id == REQUEST_ID
            assert result.job_id == JOB_ID
            assert result.start_time == start_time
            assert result.end_time == end_time
            assert result.manifests[0] in manifests

@pytest.mark.parametrize("manifests, expected_exception, exception_text", [
    # Success
    (["MANIFEST1", "MANIFEST2"], None, None),
    # Fail - missing manifests
    ([], DispatcherException, "Error: At least one manifest is required for the schedule.  Manifest list is empty."), 
 ])

def test_create_immediate_schedule_with_various_parameters(db_connection: SqliteManager, manifests, expected_exception, exception_text):
    s = SingleSchedule(request_id=REQUEST_ID,
                 job_id=JOB_ID,
                 manifests=manifests)
    db_connection.clear_database()
    if expected_exception:
        with pytest.raises(expected_exception) as excinfo:
            db_connection.create_schedule(s)
        assert exception_text in str(excinfo.value)
    else:
        db_connection.create_schedule(s)
        results = db_connection.get_immediate_schedules_in_priority_order()
        assert len(results) == 2
        for result in results:
            assert result.request_id == REQUEST_ID
            assert result.job_id == JOB_ID
            assert result.manifests[0] in manifests

@pytest.mark.parametrize("duration, minutes, hours, day_month, month, day_week, manifests, expected_exception, exception_text", [
    # Success
    ("P7D", "0", "0", "*", "*", "1-5", ["MANIFEST1", "MANIFEST2"], None, None),
    # Fail - missing manifests
    ("P7D", "*/31", "0", "*", "*", "1-5", [], DispatcherException, "Error: At least one manifest is required for the schedule.  Manifest list is empty."), 
 ])

def test_create_repeated_schedule_with_various_paramters(db_connection: SqliteManager, 
                                                duration, minutes, hours, 
                                                day_month, month, day_week, 
                                                manifests, expected_exception, exception_text):
    rs = RepeatedSchedule(request_id=REQUEST_ID,
                         job_id=JOB_ID,
                         cron_duration=duration, cron_minutes=minutes, 
                         cron_hours=hours, cron_day_month=day_month,
                         cron_month=month, cron_day_week=day_week,
                         manifests=manifests)
    db_connection.clear_database()
    if expected_exception:
        with pytest.raises(expected_exception) as excinfo:
            db_connection.create_schedule(rs)
        assert exception_text in str(excinfo.value)
    else:
        db_connection.create_schedule(rs)
        results = db_connection.get_repeated_schedules_in_priority_order()
        assert len(results) == 2
        for result in results:
            assert result.request_id == REQUEST_ID
            assert result.job_id == JOB_ID
            assert result.cron_duration == duration
            assert result.cron_minutes == minutes
            assert result.cron_hours == hours
            assert result.cron_day_month == day_month
            assert result.cron_month == month
            assert result.cron_day_week == day_week
            assert result.manifests[0] in manifests
