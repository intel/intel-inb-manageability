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
    ss1 = SingleSchedule(request_id="REQ123", 
                        start_time=None,
                        end_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                        manifests=["MANIFEST1", "MANIFEST2"])
    with pytest.raises(DispatcherException) as excinfo:
        db_connection.create_schedule(ss1)
    assert "Transaction failed: NOT NULL constraint failed: single_schedule.start_time" in str(excinfo.value)
    
def test_raise_exeption_when_create_single_schedule_with_no_manifests(db_connection: SqliteManager):
    ss1 = SingleSchedule(request_id="REQ123", 
                        start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                        end_time=datetime.strptime("2024-01-01T02:00:00", "%Y-%m-%dT%H:%M:%S",),
                        manifests=[])
    with pytest.raises(DispatcherException) as excinfo:
        db_connection.create_schedule(ss1)
    assert "Error: At least one job is required for the schedule.  Jobs list is empty." in str(excinfo.value)
                    
def test_raise_exception_when_create_repeated_schedule_with_no_manifests(db_connection: SqliteManager):
    rs1 = RepeatedSchedule(request_id="REQ123",
                        cron_minutes="*/3",
                        manifests=[])
    with pytest.raises(DispatcherException) as excinfo:                                
        db_connection.create_schedule(rs1)
    assert "Error: At least one job is required for the schedule.  Jobs list is empty." in str(excinfo.value)
        
def test_create_simple_schedule(db_connection: SqliteManager):
    db_connection.clear_database()
    ss1 = SingleSchedule(request_id="REQ123", 
                        start_time=datetime.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), 
                        end_time=datetime.strptime("2024-01-02T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                        manifests=["MANIFEST1", "MANIFEST2"])
    ss2 = SingleSchedule(request_id="REQ234", 
                        start_time=datetime.strptime("2024-05-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
                        manifests=["MANIFEST3", "MANIFEST4"])

    db_connection.create_schedule(ss1)
    db_connection.create_schedule(ss2)
    res = db_connection.get_all_single_schedules_in_priority_order()
    assert len(res) == 4
    assert res[0].request_id == "REQ123"
    assert res[1].request_id == "REQ234"
    assert res[2].request_id == "REQ123"
    assert res[3].request_id == "REQ234"
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

        
    # def test_create_repeated_schedule(self):
    #     rs1 = RepeatedSchedule(request_id="REQ123", 
    #                         cron_duration="*",
    #                         cron_minutes="0",
    #                         cron_hours="0",
    #                         cron_day_week="1-5",
    #                         manifests=["MANIFEST1", "MANIFEST2"])
    #     rs2 = RepeatedSchedule(request_id="REQ234", 
    #                         cron_duration="P1D",
    #                         cron_minutes="*/3",
    #                         manifests=["MANIFEST3", "MANIFEST4"])

    #     self.db.create_schedule(rs1)
    #     self.db.create_schedule(rs2)
    #     res1 = self.db.select_repeated_schedule_by_request_id("REQ123")
    #     res2 = self.db.select_repeated_schedule_by_request_id("REQ234")
    
    #     self.assertEqual(res1[0].schedule_id, 1)
    #     self.assertEqual(res1[0].request_id, "REQ123")
    #     self.assertEqual(res1[0].cron_duration, "*")
    #     self.assertEqual(res1[0].cron_minutes, "0")
    #     self.assertEqual(res1[0].cron_hours, "0")
    #     self.assertEqual(res1[0].cron_day_month, "*")
    #     self.assertEqual(res1[0].cron_month, "*")
    #     self.assertEqual(res1[0].cron_day_week, "1-5")
    #     self.assertEqual(res1[0].manifests, ["MANIFEST1", "MANIFEST2"])
             
    #     self.assertEqual(res2[0].schedule_id, 2)
    #     self.assertEqual(res2[0].request_id, "REQ234")
    #     self.assertEqual(res2[0].cron_duration, "P1D")
    #     self.assertEqual(res2[0].cron_minutes, "*/3")
    #     self.assertEqual(res2[0].cron_hours, "*")
    #     self.assertEqual(res2[0].cron_day_month, "*")
    #     self.assertEqual(res2[0].cron_month, "*")
    #     self.assertEqual(res2[0].cron_day_week, "*")
    #     self.assertEqual(res2[0].manifests, ["MANIFEST3", "MANIFEST4"])          
