from telemetry.telemetry_handling import (
    _set_timestamp, TelemetryTimer, send_initial_telemetry, publish_telemetry_update, get_query_related_info)
from mock import patch, Mock
from unittest import TestCase
import unittest
import time
from future import standard_library
standard_library.install_aliases()

info = {'timestamp': 1637019250.2020352, 'type': 'static_telemetry',
        'values': {'totalPhysicalMemory': '8209653760', 'cpuId': 'Intel(R) Core(TM) i5-8259U CPU @ 2.30GHz',
                   'biosVendor': 'Intel Corp.', 'biosVersion': 'BECFL357.86A.0051.2018.1015.1513',
                   'biosReleaseDate': '2018-10-15 00:00:00', 'systemManufacturer': 'Intel(R) Client Systems',
                   'systemProductName': 'NUC8i5BEK',
                   'osInformation': 'Linux 5.4.0-72-generic UTC 2021 x86_64 x86_64',
                   'diskInformation': '[{"NAME": "loop0", "SIZE": "38400000", "SSD": "True"}]'}}


class TestTelemetryHandling(TestCase):

    def test_set_collect_time(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)
        handler.set_collect_time(0.004)
        handler.wait_collect(max_sleep_time=0.004)

        self.assertTrue(handler.time_to_collect())

    def test_set_publish_time(self):
        collect_time = 0.05
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)
        handler.set_publish_time(0.05)
        handler.wait_collect(max_sleep_time=0.05)

        self.assertTrue(handler.time_to_publish())

    def test_telemetry_timestamp(self):
        telem = {"item1": "foo", "item2": "bar"}

        the_time = time.time()

        telem = _set_timestamp(telem, telemetry_type="static_telemetry")

        self.assertTrue(float(telem['timestamp']) >= the_time)

    def test_telemetry_timer_1(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)

        handler.wait_collect()
        self.assertFalse(handler.time_to_publish())

    def test_telemetry_timer_with_max_sleep_time_1(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)

        handler.wait_collect(max_sleep_time=0.003)

        self.assertTrue(handler.time_to_collect())
        self.assertFalse(handler.time_to_publish())

    def test_telemetry_timer_with_max_sleep_time_2(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)

        handler.wait_collect(max_sleep_time=0.001)

        self.assertFalse(handler.time_to_collect())

    def test_telemetry_timer_with_max_sleep_time_3(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)

        handler.wait_collect(max_sleep_time=0.002)
        handler.wait_collect(max_sleep_time=0.002)
        self.assertTrue(handler.time_to_collect())

    def test_telemetry_timer_2(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)

        i = 0
        while i < 11:
            handler.wait_collect()
            i = i + 1

        self.assertTrue(handler.time_to_publish())
        self.assertFalse(handler.time_to_publish())

    @patch('telemetry.telemetry_handling.publish_dynamic_telemetry')
    @patch('telemetry.telemetry_handling.publish_static_telemetry')
    def test_publish_initial_telemetry(self, mock_static, mock_publish):
        send_initial_telemetry(None, None)
        mock_static.assert_called_once()
        assert mock_publish.call_count == 2

    @patch('telemetry.telemetry_handling.publish_dynamic_telemetry', autospec=True)
    @patch('telemetry.telemetry_handling.get_dynamic_telemetry', autospec=True)
    def test_publish_telemetry_update_succeeds(
            self,
            mock_get_dynamic_telemetry,
            mock_publish_dynamic_telemetry):
        mock_get_dynamic_telemetry.return_value = {
            "values": {
                "a": "a",
                "b": "b"
            }
        }
        mock_client = Mock()
        publish_telemetry_update(mock_client, "topic", True, "b")

        assert mock_publish_dynamic_telemetry.call_count == 1
        args, kwargs = mock_publish_dynamic_telemetry.call_args
        telemetry = args[2]["values"]
        assert telemetry.get("a") is None
        assert telemetry.get("b") is not None

    def test_get_all_query_related_info(self):
        collect_time = 0.003
        publish_time = 0.03
        handler = TelemetryTimer(collect_time, publish_time)
        result = get_query_related_info("all", info)
        self.assertEqual(info, result)


if __name__ == '__main__':
    unittest.main()
