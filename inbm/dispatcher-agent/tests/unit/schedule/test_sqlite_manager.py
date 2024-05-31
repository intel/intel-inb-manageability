from unittest import TestCase

from dispatcher.schedule.sqlite_manager import SqliteManager
from dispatcher.schedule.schedules import SingleSchedule, RepeatedSchedule
from dispatcher.dispatcher_exception import DispatcherException

class TestSqliteManager(TestCase):
    
    def setUp(self) -> None:
        self.db = SqliteManager(":memory:")
     
    def test_raise_exception_when_create_single_schedule_with_invalid_start_time(self):
        ss1 = SingleSchedule(request_id="REQ123", 
                            start_time=None,
                            end_time="2024-01-02T00:00:00", 
                            manifests=["MANIFEST1", "MANIFEST2"])
        with self.assertRaisesRegex(DispatcherException, 
                                    'Error adding single schedule to database: NOT NULL constraint failed: single_schedule.start_time'):
            self.db.create_schedule(ss1)
    
    def test_raise_exception_when_create_single_schedule_with_no_manifests(self):
        ss1 = SingleSchedule(request_id="REQ123", 
                            start_time="2024-01-01T00:00:00",
                            end_time="2024-01-02T00:00:00", 
                            manifests=[])
        with self.assertRaisesRegex(DispatcherException, 
                                    'Error: At least one manifest is required for the schedule.  Manifests list is empty.'):
            self.db.create_schedule(ss1)
                    
    def test_raise_exception_when_create_repeated_schedule_with_no_manifests(self):
        rs1 = RepeatedSchedule(request_id="REQ123",
                            cron_duration=None,
                            cron_minutes="*/3",
                            manifests=[])
        with self.assertRaisesRegex(DispatcherException, 
                                    'Error: At least one manifest is required for the schedule.  Manifests list is empty.'):
            self.db.create_schedule(rs1)
        
    def test_create_simple_schedule(self):
        ss1 = SingleSchedule(request_id="REQ123", 
                            start_time="2024-01-01T00:00:00", 
                            end_time="2024-01-02T00:00:00", 
                            manifests=["MANIFEST1", "MANIFEST2"])
        ss2 = SingleSchedule(request_id="REQ234", 
                            start_time="2024-05-01T00:00:00", 
                            manifests=["MANIFEST3", "MANIFEST4"])

        self.db.create_schedule(ss1)
        self.db.create_schedule(ss2)
        res1 = self.db.select_single_schedule_by_request_id("REQ123")
        res2 = self.db.select_single_schedule_by_request_id("REQ234")
        
        self.assertEqual(res1[0].id, 1)
        self.assertEqual(res1[0].request_id, "REQ123")
        self.assertEqual(res1[0].start_time, "2024-01-01T00:00:00")
        self.assertEqual(res1[0].end_time, "2024-01-02T00:00:00")
        self.assertEqual(res1[0].manifests, ["MANIFEST1", "MANIFEST2"])
        
        self.assertEqual(res2[0].request_id, "REQ234")
        self.assertEqual(res2[0].start_time, "2024-05-01T00:00:00")
        #self.assertEqual(res2[0].end_time, None)
        self.assertEqual(res2[0].manifests, ["MANIFEST3", "MANIFEST4"])
        
    def test_create_repeated_schedule(self):
        rs1 = RepeatedSchedule(request_id="REQ123", 
                            cron_duration="*",
                            cron_minutes="0",
                            cron_hours="0",
                            cron_day_week="1-5",
                            manifests=["MANIFEST1", "MANIFEST2"])
        rs2 = RepeatedSchedule(request_id="REQ234", 
                            cron_duration="P1D",
                            cron_minutes="*/3",
                            manifests=["MANIFEST3", "MANIFEST4"])

        self.db.create_schedule(rs1)
        self.db.create_schedule(rs2)
        res1 = self.db.select_repeated_schedule_by_request_id("REQ123")
        res2 = self.db.select_repeated_schedule_by_request_id("REQ234")
    
        self.assertEqual(res1[0].id, 1)
        self.assertEqual(res1[0].request_id, "REQ123")
        self.assertEqual(res1[0].cron_duration, "*")
        self.assertEqual(res1[0].cron_minutes, "0")
        self.assertEqual(res1[0].cron_hours, "0")
        self.assertEqual(res1[0].cron_day_month, "*")
        self.assertEqual(res1[0].cron_month, "*")
        self.assertEqual(res1[0].cron_day_week, "1-5")
        self.assertEqual(res1[0].manifests, ["MANIFEST1", "MANIFEST2"])
             
        self.assertEqual(res2[0].id, 2)
        self.assertEqual(res2[0].request_id, "REQ234")
        self.assertEqual(res2[0].cron_duration, "P1D")
        self.assertEqual(res2[0].cron_minutes, "*/3")
        self.assertEqual(res2[0].cron_hours, "*")
        self.assertEqual(res2[0].cron_day_month, "*")
        self.assertEqual(res2[0].cron_month, "*")
        self.assertEqual(res2[0].cron_day_week, "*")
        self.assertEqual(res2[0].manifests, ["MANIFEST3", "MANIFEST4"])          
   