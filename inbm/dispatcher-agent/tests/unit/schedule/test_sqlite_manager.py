import pytest

from datetime import datetime

from dispatcher.schedule.sqlite_manager import SqliteManager
from dispatcher.schedule.schedules import SingleSchedule, RepeatedSchedule
from dispatcher.dispatcher_exception import DispatcherException


@pytest.fixture
def db_connection():
    # Setup: create a new in-memory database connection using the custom class
    db_conn = SqliteManager(":memory:")

    # Yield the custom database connection to the test
    yield db_conn

    # Teardown: close the connection after the test is done
    db_conn.close()

@pytest.mark.parametrize("start_time, end_time, manifests, expected_exception, exception_text", [
    # Success
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     ["MANIFEST1", "MANIFEST2"], None, None),
    # # Success - no end time
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
     None, 
     ["MANIFEST1", "MANIFEST2"], None, None),
    # Fail - no start time
    (None, datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
    ["MANIFEST1"], DispatcherException, "Transaction failed: NOT NULL constraint failed: single_schedule.start_time"),
    # Fail - no manifests
    (datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
    datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
    [], DispatcherException, "Error: At least one manifest is required for the schedule.  Manifest list is empty."),
])

def test_create_single_schedule_with_various_parameters(db_connection: SqliteManager, 
                                                start_time, end_time, manifests, 
                                                expected_exception, exception_text):
    ss = SingleSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
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
        results = db_connection.get_all_single_schedules_in_priority_order()
        assert len(results) == 2
        for result in results:
            assert result.request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
            assert result.job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
            assert result.start_time == start_time
            assert result.end_time == end_time
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
    rs = RepeatedSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
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
        results = db_connection.get_all_repeated_schedules_in_priority_order()
        assert len(results) == 2
        for result in results:
            assert result.request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
            assert result.job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
            assert result.cron_duration == duration
            assert result.cron_minutes == minutes
            assert result.cron_hours == hours
            assert result.cron_day_month == day_month
            assert result.cron_month == month
            assert result.cron_day_week == day_week
            assert result.manifests[0] in manifests
