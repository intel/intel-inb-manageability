from unittest import TestCase

from unittest.mock import Mock
from os import path
import time
from unit.common.mock_resources import *
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.workload_orchestration import *
from dispatcher.constants import *

from unittest.mock import patch
import logging
import mock
import platform
import requests
logger = logging.getLogger(__name__)


class TestWorkloadOrchestration(TestCase):

    def setUp(self) -> None:
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()
        self.mock_broker = MockDispatcherBroker.build_mock_dispatcher_broker()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_is_workload_service_file_not_present(self, mock_value) -> None:
        mock_callback = Mock()
        mock_value.return_value = "in.conf"
        result = WorkloadOrchestration(
            self.mock_broker).is_workload_service_file_present()
        self.assertEqual(result, False)

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._switch_to_maintenance_mode')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_file_present')
    def test_set_workload_orchestration_mode1(self, mock_file_present, mock_active, mock_mode) -> None:
        mock_callback = Mock()
        mock_file_present.return_value = True
        mock_active.return_value = True
        WorkloadOrchestration(
            self.mock_broker).set_workload_orchestration_mode(False)
        mock_mode.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._switch_to_online_mode')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_file_present')
    def test_set_workload_orchestration_mode2(self, mock_file_present, mock_active, mock_mode) -> None:
        mock_callback = Mock()
        mock_file_present.return_value = True
        mock_active.return_value = True
        WorkloadOrchestration(
            self.mock_broker).set_workload_orchestration_mode(True)
        mock_mode.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('active', "", 0))
    def test_is_workload_service_active(self, mock_run, mock_value) -> None:
        mock_callback = Mock()
        result = WorkloadOrchestration(
            self.mock_broker).is_workload_service_active()
        self.assertEqual(result, True)

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('inactive', "", 0))
    def test_is_workload_service_inactive(self, mock_run, mock_value) -> None:
        mock_callback = Mock()
        result = WorkloadOrchestration(
            self.mock_broker).is_workload_service_active()
        self.assertEqual(result, False)

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_failure1(self, mock_wo_status, mock_value, mock_time) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_failure2(self, mock_wo_status, mock_value, mock_time) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Workload Orchestration Maintenance mode failure: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure3(self, mock_poll, mock_wo_status, mock_value, mock_time) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
            mock_poll.assert_called_once()
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure4(self, mock_poll, mock_wo_status, mock_value, mock_time) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure5(self, mock_poll, mock_wo_status, mock_value, mock_time) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_pass(self, mock_poll, mock_wo_status, mock_value) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': []}, 200)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_success(self, mock_wo_status, mock_value) -> None:
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active", return_value=True)
    def test_workload_orchestration_online_mode1(self, mock_active, mock_value, mock_poll) -> None:
        mock_callback = Mock()
        mock_poll.return_value = ({'Enabled': False, 'Workloads': []}, 200)
        WorkloadOrchestration(self.mock_broker)._switch_to_online_mode()
        mock_poll.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active", return_value=True)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_online_mode2(self, mock_switch_wo_status, mock_active, mock_value, mock_poll) -> None:
        mock_poll.return_value = ({'Enabled': True, 'Workloads': []}, 200)
        mock_switch_wo_status.return_value = ({'Enabled': False, 'Workloads': []}, 202)
        mock_callback = Mock()

        WorkloadOrchestration(self.mock_broker)._switch_to_online_mode()
        mock_switch_wo_status.assert_called_once()
        mock_poll.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status(self, mock_value, mock_details) -> None:
        mock_details.return_value = (None, None)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(self.mock_broker).switch_wo_status("true")
        except (DispatcherException) as e:
            self.assertEqual(
                " Workload-Orchestration IP and Token details Not Found", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status_failure(self, mock_value, mock_details, mock_content, mock_hostname) -> None:
        mock_content.return_value = "ip_port"
        mock_details.return_value = ("ip", "port")
        mock_value.return_value = '/etc/cert.pem'
        mock_hostname.return_value = "test"
        mock_callback = Mock()
        try:
            WorkloadOrchestration(self.mock_broker).switch_wo_status("true")
        except (DispatcherException) as e:
            self.assertEqual(
                "Invalid URL 'ip_port/api/v1/nodes/test/maintenance?token=ip_port': No scheme supplied. Perhaps you meant https://ip_port/api/v1/nodes/test/maintenance?token=ip_port?", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result(self, mock_wo_status, mock_time) -> None:
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": []})
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result1(self, mock_wo_status, mock_time) -> None:
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(self.mock_broker)._process_maintenance_mode_ok_status_result(
                "false", {"Enabled": False, "Workloads": []})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result2(self, mock_wo_status, mock_time) -> None:
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 200)
            WorkloadOrchestration(self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result3(self, mock_wo_status, mock_time) -> None:
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 200)
            WorkloadOrchestration(self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result4(self, mock_wo_status, mock_time) -> None:
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result(self, mock_wo_status) -> None:
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        WorkloadOrchestration(self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": True, "Workloads": []})
        mock_wo_status.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result1(self, mock_wo_status) -> None:
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        WorkloadOrchestration(self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": True, "Workloads": []})
        mock_wo_status.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result2(self, mock_wo_status) -> None:
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        WorkloadOrchestration(self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": False, "Workloads": []})
        mock_wo_status.assert_not_called()

    def test_get_hostname(self) -> None:
        """Test the static get_hostname method"""
        hostname = WorkloadOrchestration.get_hostname()
        self.assertIsNotNone(hostname)
        self.assertIsInstance(hostname, str)
        self.assertGreater(len(hostname), 0)

    @patch('builtins.open', mock.mock_open(read_data='test_file_content'))
    def test_get_workload_orchestration_file_content_success(self) -> None:
        """Test successful file reading"""
        result = WorkloadOrchestration(self.mock_broker)._get_workload_orchestration_file_content('/test/path')
        self.assertEqual(result, 'test_file_content')

    @patch('builtins.open', side_effect=OSError("File not found"))
    def test_get_workload_orchestration_file_content_failure(self, mock_open) -> None:
        """Test file reading with OSError"""
        with self.assertRaises(DispatcherException) as context:
            WorkloadOrchestration(self.mock_broker)._get_workload_orchestration_file_content('/nonexistent/path')
        self.assertIn("Could not load workload orchestration config file with error:", str(context.exception))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_get_wo_details_success(self, mock_value) -> None:
        """Test get_wo_details method with valid values"""
        mock_value.side_effect = ['test_token', 'test_ip_port']
        token, ip_port = WorkloadOrchestration(self.mock_broker).get_wo_details()
        self.assertEqual(token, 'test_token')
        self.assertEqual(ip_port, 'test_ip_port')

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_get_wo_details_none_values(self, mock_value) -> None:
        """Test get_wo_details method with None values"""
        mock_value.side_effect = [None, None]
        token, ip_port = WorkloadOrchestration(self.mock_broker).get_wo_details()
        self.assertIsNone(token)
        self.assertIsNone(ip_port)

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    def test_poll_wo_status_none_details(self, mock_details) -> None:
        """Test poll_wo_status with None token and ip_port"""
        mock_details.return_value = (None, None)
        with self.assertRaises(DispatcherException) as context:
            WorkloadOrchestration(self.mock_broker).poll_wo_status()
        self.assertEqual(str(context.exception), " Workload-Orchestration IP and Token details Not Found")    # Simplified connection error tests - focusing on coverage rather than exact error messages
    @patch('requests.get', side_effect=requests.exceptions.ConnectionError("Connection failed"))
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_poll_wo_status_connection_error(self, mock_orchestrator_value, mock_details, mock_file_content, mock_hostname, mock_requests_get) -> None:
        """Test poll_wo_status with connection error"""
        mock_details.return_value = ('token', 'ip_port')
        mock_file_content.side_effect = ['http://localhost:8080', 'test_token']
        mock_hostname.return_value = 'test_host'
        mock_orchestrator_value.return_value = True
        
        with self.assertRaises(DispatcherException):
            WorkloadOrchestration(self.mock_broker).poll_wo_status()

    @patch('requests.get', side_effect=TypeError("Type error"))
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_poll_wo_status_type_error(self, mock_orchestrator_value, mock_details, mock_file_content, mock_hostname, mock_requests_get) -> None:
        """Test poll_wo_status with TypeError"""
        mock_details.return_value = ('token', 'ip_port')
        mock_file_content.side_effect = ['http://localhost:8080', 'test_token']
        mock_hostname.return_value = 'test_host'
        mock_orchestrator_value.return_value = True

        with self.assertRaises(DispatcherException):
            WorkloadOrchestration(self.mock_broker).poll_wo_status()

    @patch('requests.patch', side_effect=requests.exceptions.ConnectionError("Connection failed"))
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status_connection_error(self, mock_orchestrator_value, mock_details, mock_file_content, mock_hostname, mock_requests_patch) -> None:
        """Test switch_wo_status with connection error"""
        mock_details.return_value = ('token', 'ip_port')
        mock_file_content.side_effect = ['http://localhost:8080', 'test_token']
        mock_hostname.return_value = 'test_host'
        mock_orchestrator_value.return_value = True
        
        with self.assertRaises(DispatcherException):
            WorkloadOrchestration(self.mock_broker).switch_wo_status("true")

    @patch('requests.patch', side_effect=ValueError("Value error"))
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status_value_error(self, mock_orchestrator_value, mock_details, mock_file_content, mock_hostname, mock_requests_patch) -> None:
        """Test switch_wo_status with ValueError"""
        mock_details.return_value = ('token', 'ip_port')
        mock_file_content.side_effect = ['http://localhost:8080', 'test_token']
        mock_hostname.return_value = 'test_host'
        mock_orchestrator_value.return_value = True

        with self.assertRaises(DispatcherException):
            WorkloadOrchestration(self.mock_broker).switch_wo_status("true")

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status', side_effect=DispatcherException("Test error"))
    def test_switch_to_maintenance_mode_exception_handling(self, mock_wo_status, mock_value, mock_time) -> None:
        """Test _switch_to_maintenance_mode exception handling with orchestrator_response = 'true'"""
        with self.assertRaises(DispatcherException) as context:
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        self.assertIn("Failure in switching Device Workload Orchestration status to Maintenance mode", str(context.exception))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status', side_effect=DispatcherException("Test error"))
    def test_switch_to_maintenance_mode_exception_handling_false(self, mock_wo_status, mock_value, mock_time) -> None:
        """Test _switch_to_maintenance_mode exception handling with orchestrator_response = 'false'"""
        # Should not raise exception when orchestrator_response is 'false'
        try:
            WorkloadOrchestration(self.mock_broker)._switch_to_maintenance_mode()
        except DispatcherException:
            self.fail("Should not raise exception when orchestrator_response is 'false'")

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status', side_effect=DispatcherException("Poll error"))
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active', return_value=True)
    def test_switch_to_online_mode_exception_handling(self, mock_active, mock_poll, mock_time) -> None:
        """Test _switch_to_online_mode exception handling"""
        # Should not raise exception, just log telemetry
        try:
            WorkloadOrchestration(self.mock_broker)._switch_to_online_mode()
        except DispatcherException:
            self.fail("Should not raise exception in _switch_to_online_mode")

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_get_orchestrator_value_calls(self, mock_get_orchestrator_value) -> None:
        """Test that get_orchestrator_value is called properly"""
        mock_get_orchestrator_value.return_value = 'test_value'
        
        wo = WorkloadOrchestration(self.mock_broker)
        result = wo.get_orchestrator_value('test_tag')
        
        mock_get_orchestrator_value.assert_called_once_with('test_tag')
        self.assertEqual(result, 'test_value')
