import datetime
from unittest import TestCase

from dispatcher.schedule.sqlite_manager import SqliteManager
from dispatcher.schedule.schedules import SingleSchedule, RepeatedSchedule
from dispatcher.dispatcher_exception import DispatcherException

class TestSqliteManager(TestCase):
    
    def setUp(self) -> None:
        self.db = SqliteManager(":memory:")
     
    def test_create_simple_schedule(self):
        ss = SingleSchedule(request_id="REQ123", 
                            start_time="2024-01-01T00:00:00", 
                            end_time="2024-01-02T00:00:00", 
                            manifests=["MANIFEST1", "MANIFEST2"])

        self.db.create_schedule(ss)
        ss = self.db.select_single_schedule_by_request_id("REQ123")
        self.assertEqual(ss.request_id[0], "REQ123")
        
         


            
    