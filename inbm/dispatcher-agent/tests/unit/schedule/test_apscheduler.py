from unittest.mock import Mock
from unittest import TestCase

from dispatcher.schedule.schedules import SingleSchedule
from dispatcher.schedule.apscheduler import APScheduler
from datetime import datetime, timedelta

class TestAPScheduler(TestCase):
    def setUp(self) -> None:
        mock_sqlite_mgr = Mock()
        self.scheduler = APScheduler(mock_sqlite_mgr)
    
    def test_return_true_schedulable_single_schedule(self):
        ss1 = SingleSchedule(request_id="REQ123", 
                start_time=datetime.now(),
                end_time=datetime.now() + timedelta(minutes=5), 
                manifests=["MANIFEST1", "MANIFEST2"])
        self.assertTrue(self.scheduler.is_schedulable(ss1))

    def test_return_false_too_late_to_schedule(self):
        ss1 = SingleSchedule(request_id="REQ123", 
                start_time=datetime.now() - timedelta(hours=2),
                end_time=datetime.now() - timedelta(minutes=3), 
                manifests=["MANIFEST1", "MANIFEST2"])
        self.assertFalse(self.scheduler.is_schedulable(ss1))
