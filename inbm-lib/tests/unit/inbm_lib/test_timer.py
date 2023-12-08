from unittest import TestCase

from inbm_lib.timer import Timer
from unittest.mock import patch, Mock
import time


class TestTimer(TestCase):

    def test_init_success_without_callback(self) -> None:
        new_timer = Timer(5)
        self.assertIsNotNone(new_timer)

    def test_init_success_with_callback(self) -> None:
        def callback() -> None:
            pass

        new_timer = Timer(5, callback)
        self.assertIsNotNone(new_timer)

    def test_init_fail(self) -> None:
        self.assertRaises(TypeError, Timer)

    @patch('threading.Thread.start')
    def test_timer_start(self, t_start: Mock) -> None:
        new_timer = Timer(5)
        new_timer.start()
        self.assertIsNotNone(new_timer)
        t_start.assert_called_once()

    def dummy_callback(self) -> None:
        pass

    @patch('unit.inbm_lib.test_timer.TestTimer.dummy_callback')
    def test_internal_timer(self, timer_callback: Mock) -> None:
        new_timer = Timer(1, self.dummy_callback)
        new_timer._start_internal_timer()
        time.sleep(0.01)
        self.assertIsNotNone(new_timer)
        timer_callback.assert_called_once()
        new_timer.stop()

    def test_get_remaining_wait_time(self) -> None:
        new_timer = Timer(10)
        new_timer.start()
        time.sleep(0.01)
        self.assertGreaterEqual(new_timer.get_remaining_wait_time(), 9)
        new_timer.stop()
