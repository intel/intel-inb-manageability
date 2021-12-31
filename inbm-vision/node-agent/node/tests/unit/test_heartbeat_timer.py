
from unittest import TestCase

from mock import patch, Mock
from node.heartbeat_timer import HeartbeatTimer


class TestTimer(TestCase):
    @patch('node.heartbeat_timer.HeartbeatTimer._start_timer')
    def test_init_success_without_callback(self, start_timer):
        new_timer = HeartbeatTimer(5, dh_callback=None)
        self.assertIsNotNone(new_timer)

    @patch('node.heartbeat_timer.HeartbeatTimer._start_timer')
    def test_init_success_with_callback(self, start_timer):
        def callback():
            pass

        new_timer = HeartbeatTimer(5, callback)
        self.assertIsNotNone(new_timer)

    def test_init_fail(self):
        self.assertRaises(TypeError, HeartbeatTimer)

    @patch('node.heartbeat_timer.HeartbeatTimer._start_timer')
    @patch('threading.Thread.start')
    def test_timer_start(self, t_start, start_timer):
        new_timer = HeartbeatTimer(5, dh_callback=None)
        new_timer._start_timer()
        self.assertIsNotNone(new_timer)

    @patch('threading.Thread.start')
    def test_timer_stop(self, t_start):
        new_timer = HeartbeatTimer(5, dh_callback=None)
        new_timer.stop()
        self.assertEqual(new_timer._running, False)

    @patch('threading.Thread.start')
    def test_timer_expired_call_method(self, t_start):
        mock_callback = Mock()
        new_timer = HeartbeatTimer(1, dh_callback=mock_callback)
        new_timer._start_internal_timer()
        mock_callback.assert_called_once()
