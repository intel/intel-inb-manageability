from telemetry.poller import Poller
from telemetry.constants import COLLECTION_INTERVAL_SECONDS, PUBLISH_INTERVAL_SECONDS, MAX_CACHE_SIZE, \
    CONTAINER_HEALTH_INTERVAL_SECONDS, SOFTWARE_BOM_INTERVAL_HOURS, ENABLE_SOFTWARE_BOM
from mock import patch
from unittest import TestCase
from telemetry.software_checker import *
from telemetry.shared import *
from inbm_lib.mqttclient.mqtt import MQTT


class MockMQTT(MQTT):
    def __init__(self) -> None:
        pass


class TestTelemetry(TestCase):

    def test_return_false_when_outside_lower_bound(self) -> None:
        v = Poller.is_between_bounds("MIN_MEMORY", "1", 2, 5)
        self.assertFalse(v)

    def test_return_false_when_outside_upper_bound(self) -> None:
        v = Poller.is_between_bounds("MIN_MEMORY", "6", 2, 5)
        self.assertFalse(v)

    def test_return_false_when_not_integer(self) -> None:
        v = Poller.is_between_bounds("MIN_MEMORY", "a", 2, 5)
        self.assertFalse(v)

    def test_return_true_when_inside_bound(self) -> None:
        v = Poller.is_between_bounds("MIN_MEMORY", "3", 2, 5)
        self.assertTrue(v)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    @patch('telemetry.telemetry_handling.TelemetryTimer.set_collect_time')
    def test_set_configuration_value_collect_time(self, mock_set_time, mock_run) -> None:
        Poller().set_configuration_value("100", COLLECTION_INTERVAL_SECONDS)
        mock_set_time.assert_called_once()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    @patch('telemetry.telemetry_handling.TelemetryTimer.set_publish_time')
    def test_set_configuration_value_publish_time(self, mock_set_time, mock_run) -> None:
        Poller().set_configuration_value("150", PUBLISH_INTERVAL_SECONDS)
        mock_set_time.assert_called_once()

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_set_configuration_value_cache_size(self, mock_run) -> None:
        poller = Poller()
        poller.set_configuration_value("150", MAX_CACHE_SIZE)
        self.assertEqual(poller._max_cache_size, 150)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_set_configuration_value_container_health_interval(self, mock_run) -> None:
        poller = Poller()
        poller.set_configuration_value("300", CONTAINER_HEALTH_INTERVAL_SECONDS)
        self.assertEqual(poller._container_health_interval_seconds, 300)
        self.assertEqual(poller._container_health_temp, 300)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_set_configuration_value_software_bom_interval(self, mock_run) -> None:
        poller = Poller()
        poller.set_configuration_value("24", SOFTWARE_BOM_INTERVAL_HOURS)
        self.assertEqual(poller._swbom_interval_seconds, 86400)
        self.assertEqual(poller._swbom_timer_seconds, 86400)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner().run', return_value=("", "", 0))
    def test_set_configuration_value_enable_software_bom(self, mock_run) -> None:
        poller = Poller()
        poller.set_configuration_value("False", ENABLE_SOFTWARE_BOM)
        self.assertEqual(poller._enable_swbom, False)

    @patch('telemetry.software_checker.are_docker_and_trtl_on_system')
    @patch('telemetry.iahost.is_iahost')
    def test_loop_telemetry(self, mock_iahost, mock_on_system) -> None:
        mock_on_system.return_value = True
        poller = Poller()
        mock_iahost.return_value = False
        poller.loop_telemetry(MockMQTT())
        mock_iahost.assert_called_once()

    @patch('telemetry.software_checker.are_docker_and_trtl_on_system')
    @patch('telemetry.iahost.rm_service_active')
    @patch('telemetry.iahost.is_iahost')
    def test_loop_telemetry_service(self, mock_iahost, mock_service, mock_on_system) -> None:
        mock_on_system.return_value = True
        poller = Poller()
        mock_iahost.return_value = True
        mock_service.return_value = False
        poller.loop_telemetry(MockMQTT())
        mock_iahost.assert_called_once()
        mock_service.assert_called_once()
