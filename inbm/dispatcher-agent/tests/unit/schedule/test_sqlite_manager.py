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


def test_raise_exception_when_create_single_schedule_with_invalid_start_time(db_connection: SqliteManager):
    ss1 = SingleSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                         start_time=None,
                         end_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         manifests=["MANIFEST1", "MANIFEST2"])
    with pytest.raises(DispatcherException) as excinfo:
        db_connection.create_schedule(ss1)
    assert "Transaction failed: NOT NULL constraint failed: single_schedule.start_time" in str(
        excinfo.value)


def test_raise_exeption_when_create_single_schedule_with_no_manifests(db_connection: SqliteManager):
    ss1 = SingleSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                         start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         end_time=datetime.strptime("2024-01-01T02:00:00", "%Y-%m-%dT%H:%M:%S",),
                         manifests=[])
    with pytest.raises(DispatcherException) as excinfo:
        db_connection.create_schedule(ss1)
    assert "Error: At least one job is required for the schedule.  Jobs list is empty." in str(
        excinfo.value)


def test_raise_exception_when_create_repeated_schedule_with_no_manifests(db_connection: SqliteManager):
    rs1 = RepeatedSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                           job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                           cron_minutes="*/3",
                           manifests=[])
    with pytest.raises(DispatcherException) as excinfo:
        db_connection.create_schedule(rs1)
    assert "Error: At least one job is required for the schedule.  Jobs list is empty." in str(
        excinfo.value)


def test_create_simple_schedule(db_connection: SqliteManager):
    db_connection.clear_database()
    ss1 = SingleSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                         start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         end_time=datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         manifests=["MANIFEST1", "MANIFEST2"])
    ss2 = SingleSchedule(request_id="4324a262-b7d1-46a7-b8cc-84d934c3983f",
                         job_id="swupd-492708d4-919e-4b0f-aaa9-06e5e2c55e70",
                         start_time=datetime.strptime("2024-05-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                         manifests=["MANIFEST3", "MANIFEST4"])

    db_connection.create_schedule(ss1)
    db_connection.create_schedule(ss2)
    res = db_connection.get_all_single_schedules_in_priority_order()
    assert len(res) == 4
    assert res[0].request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
    assert res[1].request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
    assert res[2].request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
    assert res[3].request_id == "4324a262-b7d1-46a7-b8cc-84d934c3983f"
    assert res[0].job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
    assert res[1].job_id == "swupd-492708d4-919e-4b0f-aaa9-06e5e2c55e70"
    assert res[2].job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
    assert res[3].job_id == "swupd-492708d4-919e-4b0f-aaa9-06e5e2c55e70"
    assert res[0].start_time == datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[1].start_time == datetime.strptime("2024-05-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[2].start_time == datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[3].start_time == datetime.strptime("2024-05-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[0].end_time == datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[1].end_time == None
    assert res[2].end_time == datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S")
    assert res[3].end_time == None
    assert res[0].manifests == ["MANIFEST1"]
    assert res[1].manifests == ["MANIFEST3"]
    assert res[2].manifests == ["MANIFEST2"]
    assert res[3].manifests == ["MANIFEST4"]

def test_create_repeated_schedule(db_connection: SqliteManager):
    db_connection.clear_database()
    rs1 = RepeatedSchedule(request_id="bfe02847-caa3-4467-82e2-3cdb12e30c8f",
                        job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                        cron_duration="*",
                        cron_minutes="0",
                        cron_hours="0",
                        cron_day_week="1-5",
                        manifests=["MANIFEST1", "MANIFEST2"])
    rs2 = RepeatedSchedule(request_id="d1d0f264-8d78-4460-9027-1354a784195d",
                        job_id="swupd-88fff0ef-4fae-43a5-beb7-fe7d8d5e31cd",
                        cron_duration="P1D",
                        cron_minutes="*/3",
                        manifests=["MANIFEST3", "MANIFEST4"])

    db_connection.create_schedule(rs1)
    db_connection.create_schedule(rs2)
    res = db_connection.get_all_repeated_schedules_in_priority_order()

    assert len(res) == 4
    assert res[0].request_id == "bfe02847-caa3-4467-82e2-3cdb12e30c8f"
    assert res[2].request_id == "bfe02847-caa3-4467-82e2-3cdb12e30c8f"
    assert res[0].job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
    assert res[2].job_id == "swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"
    assert res[0].cron_duration == "*"
    assert res[0].cron_minutes == "0"
    assert res[0].cron_hours == "0"
    assert res[0].cron_day_month == "*"
    assert res[0].cron_month == "*"
    assert res[0].cron_day_week == "1-5"

    assert res[1].request_id == "d1d0f264-8d78-4460-9027-1354a784195d"
    assert res[3].request_id == "d1d0f264-8d78-4460-9027-1354a784195d"
    assert res[1].job_id == "swupd-88fff0ef-4fae-43a5-beb7-fe7d8d5e31cd"
    assert res[3].job_id == "swupd-88fff0ef-4fae-43a5-beb7-fe7d8d5e31cd"
    assert res[1].cron_duration == "P1D"
    assert res[1].cron_minutes == "*/3"
    assert res[1].cron_hours == "*"
    assert res[1].cron_day_month == "*"
    assert res[1].cron_month == "*"
    assert res[1].cron_day_week == "*"
    assert res[0].manifests == ["MANIFEST1"]
    assert res[1].manifests == ["MANIFEST3"]
    assert res[2].manifests == ["MANIFEST2"]
    assert res[3].manifests == ["MANIFEST4"]
