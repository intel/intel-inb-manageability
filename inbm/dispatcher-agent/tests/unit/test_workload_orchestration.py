from unittest import TestCase

from mock import Mock
from os import path
import time
from unit.common.mock_resources import *
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.workload_orchestration import *
from dispatcher.constants import *

from mock import patch
import logging
import mock
logger = logging.getLogger(__name__)


class TestWorkloadOrchestration(TestCase):

    def setUp(self):
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()
        self.mock_broker = MockDispatcherBroker.build_mock_dispatcher_broker()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_is_workload_service_file_not_present(self, mock_value):
        mock_callback = Mock()
        mock_value.return_value = "in.conf"
        result = WorkloadOrchestration(mock_callback, self.mock_broker).is_workload_service_file_present()
        self.assertEqual(result, False)

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._switch_to_maintenance_mode')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_file_present')
    def test_set_workload_orchestration_mode1(self, mock_file_present, mock_active, mock_mode):
        mock_callback = Mock()
        mock_file_present.return_value = True
        mock_active.return_value = True
        WorkloadOrchestration(mock_callback, self.mock_broker).set_workload_orchestration_mode(False)
        mock_mode.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._switch_to_online_mode')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_file_present')
    def test_set_workload_orchestration_mode2(self, mock_file_present, mock_active, mock_mode):
        mock_callback = Mock()
        mock_file_present.return_value = True
        mock_active.return_value = True
        WorkloadOrchestration(mock_callback, self.mock_broker).set_workload_orchestration_mode(True)
        mock_mode.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('active', "", 0))
    def test_is_workload_service_active(self, mock_run, mock_value):
        mock_callback = Mock()
        result = WorkloadOrchestration(mock_callback, self.mock_broker).is_workload_service_active()
        self.assertEqual(result, True)

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('inactive', "", 0))
    def test_is_workload_service_inactive(self, mock_run, mock_value):
        mock_callback = Mock()
        result = WorkloadOrchestration(mock_callback, self.mock_broker).is_workload_service_active()
        self.assertEqual(result, False)

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_failure1(self, mock_wo_status, mock_value, mock_time):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_failure2(self, mock_wo_status, mock_value, mock_time):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Workload Orchestration Maintenance mode failure: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure3(self, mock_poll, mock_wo_status, mock_value, mock_time):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
            mock_poll.assert_called_once()
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure4(self, mock_poll, mock_wo_status, mock_value, mock_time):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_failure5(self, mock_poll, mock_wo_status, mock_value, mock_time):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': ['one']}, 400)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='false')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_workload_orchestration_maintenance_mode_pass(self, mock_poll, mock_wo_status, mock_value):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': ['one']}, 202)
        mock_poll.return_value = ({'Enabled': True, 'Workloads': []}, 200)
        mock_callback = Mock()
        try:
            mock_callback = Mock()
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value', return_value='true')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_maintenance_mode_success(self, mock_wo_status, mock_value):
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_maintenance_mode()
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in checking Device Workload Orchestration status: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active", return_value=True)
    def test_workload_orchestration_online_mode1(self, mock_active, mock_value, mock_poll):
        mock_callback = Mock()
        mock_poll.return_value = ({'Enabled': False, 'Workloads': []}, 200)
        WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_online_mode()
        mock_poll.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    @patch("dispatcher.workload_orchestration.WorkloadOrchestration.is_workload_service_active", return_value=True)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_workload_orchestration_online_mode2(self, mock_switch_wo_status, mock_active, mock_value, mock_poll):
        mock_poll.return_value = ({'Enabled': True, 'Workloads': []}, 200)
        mock_switch_wo_status.return_value = ({'Enabled': False, 'Workloads': []}, 202)
        mock_callback = Mock()

        WorkloadOrchestration(mock_callback, self.mock_broker)._switch_to_online_mode()
        mock_switch_wo_status.assert_called_once()
        mock_poll.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status(self, mock_value, mock_details):
        mock_details.return_value = (None, None)
        mock_callback = Mock()
        try:
            WorkloadOrchestration(mock_callback, self.mock_broker).switch_wo_status("true")
        except (DispatcherException) as e:
            self.assertEqual(
                " Workload-Orchestration IP and Token details Not Found", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_hostname')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration._get_workload_orchestration_file_content')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_wo_details')
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.get_orchestrator_value')
    def test_switch_wo_status_failure(self, mock_value, mock_details, mock_content, mock_hostname):
        mock_content.return_value = "ip_port"
        mock_details.return_value = ("ip", "port")
        mock_value.return_value = '/etc/cert.pem'
        mock_hostname.return_value = "test"
        mock_callback = Mock()
        try:
            WorkloadOrchestration(mock_callback, self.mock_broker).switch_wo_status("true")
        except (DispatcherException) as e:
            self.assertEqual(
                "Invalid URL 'ip_port/api/v1/nodes/test/maintenance?token=ip_port': No scheme supplied. Perhaps you meant https://ip_port/api/v1/nodes/test/maintenance?token=ip_port?", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result(self, mock_wo_status, mock_time):
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(mock_callback, self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": []})
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result1(self, mock_wo_status, mock_time):
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(mock_callback, self.mock_broker)._process_maintenance_mode_ok_status_result(
                "false", {"Enabled": False, "Workloads": []})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result2(self, mock_wo_status, mock_time):
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 200)
            WorkloadOrchestration(mock_callback, self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result3(self, mock_wo_status, mock_time):
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 200)
            WorkloadOrchestration(mock_callback, self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertNotEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('time.sleep', return_value=0)
    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.poll_wo_status')
    def test_process_maintenance_mode_ok_status_result4(self, mock_wo_status, mock_time):
        try:
            mock_callback = Mock()
            mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
            WorkloadOrchestration(mock_callback, self.mock_broker)._process_maintenance_mode_ok_status_result(
                "true", {"Enabled": False, "Workloads": ['one']})
        except (DispatcherException) as e:
            self.assertEqual(
                "Failure in switching Device Workload Orchestration status to Maintenance mode: Can't proceed to OTA update ", str(e))

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result(self, mock_wo_status):
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        WorkloadOrchestration(mock_callback, self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": True, "Workloads": []})
        mock_wo_status.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result1(self, mock_wo_status):
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 400)
        WorkloadOrchestration(mock_callback, self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": True, "Workloads": []})
        mock_wo_status.assert_called_once()

    @patch('dispatcher.workload_orchestration.WorkloadOrchestration.switch_wo_status')
    def test_process_online_mode_ok_status_result2(self, mock_wo_status):
        mock_callback = Mock()
        mock_wo_status.return_value = ({'Enabled': True, 'Workloads': []}, 202)
        WorkloadOrchestration(mock_callback, self.mock_broker)._process_online_mode_ok_status_result(
            {"Enabled": False, "Workloads": []})
        mock_wo_status.assert_not_called()
