from unittest.mock import Mock, patch
from unittest import TestCase

from dispatcher.schedule.schedules import SingleSchedule
from dispatcher.schedule.apscheduler import APScheduler
from datetime import datetime, timedelta

class TestAPScheduler(TestCase):
    def setUp(self) -> None:
        mock_sqlite_mgr = Mock()
        mock_sqlite_mgr.update_status = Mock()
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

    def test_return_false_start_time_greater_than_end_time(self):
        ss1 = SingleSchedule(request_id="REQ123",
                start_time=datetime.now() + timedelta(minutes=3),
                end_time=datetime.now(),
                manifests=["MANIFEST1", "MANIFEST2"])
        self.assertFalse(self.scheduler.is_schedulable(ss1))

    def test_return_true_schedule_in_future(self):
        ss1 = SingleSchedule(request_id="REQ123",
                start_time=datetime.now() + timedelta(minutes=5),
                end_time=datetime.now()+ timedelta(hours=1),
                manifests=["MANIFEST1", "MANIFEST2"])
        self.assertTrue(self.scheduler.is_schedulable(ss1))

    def test_is_schedulable_with_other_object(self):
        ss1 = "Neither a SingleSchedule nor a RepeatedSchedule object"
        self.assertFalse(self.scheduler.is_schedulable(schedule=ss1))

    def test_add_single_schedule_job(self):
        ss1 = SingleSchedule(request_id="REQ123",
                start_time=datetime.now(),
                end_time=datetime.now() + timedelta(minutes=5),
                manifests=["MANIFEST1", "MANIFEST2", "MANIFEST3"])
        self.scheduler.add_single_schedule_job(callback=Mock(), single_schedule=ss1)
        self.assertEqual(len(self.scheduler._scheduler.get_jobs()), 3)

    def test_convert_duration_to_end_time_return_default(self):
        self.assertEqual(self.scheduler._convert_duration_to_end_time(duration="*"), "*")

    @patch('dispatcher.schedule.apscheduler.datetime', wraps=datetime)
    def test_convert_duration_to_end_time_with_second(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2024, 12, 25, 12, 0, 0)
        self.assertEqual(self.scheduler._convert_duration_to_end_time(duration="PT3600S"), datetime(2024, 12, 25, 13, 0, 0))

    @patch('dispatcher.schedule.apscheduler.datetime', wraps=datetime)
    def test_convert_duration_to_end_time_with_day(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2024, 12, 25, 12, 0, 0)
        self.assertEqual(self.scheduler._convert_duration_to_end_time(duration="P1D"), datetime(2024, 12, 26, 12, 0, 0))
