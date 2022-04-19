
from unittest import TestCase

from vision.rollback_manager import RollbackManager
from vision.configuration_constant import DEFAULT_ROLLBACK_WAIT_TIME
from mock import patch, Mock, MagicMock


class TestRollbackManager(TestCase):

    @patch('threading.Thread.start')
    def setUp(self, t_start):
        flashless_node_list = ["mock_node_1", "mock_node_2"]
        self.mock_config_mgr = Mock()
        self.mock_config_mgr.get_element = MagicMock(return_value=['10'])
        self.mock_node_connector = Mock()
        self.mock_node_connector.reset_device
        self.mock_broker = Mock()
        self.mock_broker.publish_telemetry_response
        self.rollback_mgr = RollbackManager(
            flashless_node_list, self.mock_config_mgr, self.mock_node_connector, self.mock_broker)

    @patch('threading.Thread.start')
    def test_use_default_rollback_value(self, t_start):
        flashless_node_list = ["mock_node_1", "mock_node_2"]
        mock_config_mgr = Mock()
        mock_config_mgr.get_element = MagicMock(side_effect=ValueError)
        mock_node_connector = Mock()
        mock_node_connector.reset_device
        mock_broker = Mock()
        mock_broker.publish_telemetry_response
        rollback_mgr = RollbackManager(
            flashless_node_list, mock_config_mgr, mock_node_connector, mock_broker)
        self.assertEqual(rollback_mgr._wait_time, DEFAULT_ROLLBACK_WAIT_TIME)

    @patch('threading.Thread.start')
    @patch('vision.flashless_utility.rollback_flashless_files')
    def test_rollback_pass(self, backup, t_start):
        mock_config_mgr = Mock()
        mock_config_mgr.get_element = MagicMock(return_value=["true"])
        self.rollback_mgr._config = mock_config_mgr
        self.rollback_mgr._rollback()
        backup.assert_called_once()
        assert t_start.call_count == 2
        assert self.mock_broker.publish_telemetry_response.call_count == 1

    @patch('threading.Thread.start', side_effect=OSError('Error'))
    @patch('vision.flashless_utility.rollback_flashless_files')
    def test_rollback_fail(self, backup, t_start):
        mock_config_mgr = Mock()
        mock_config_mgr.get_element = MagicMock(return_value=["true"])
        self.rollback_mgr._config = mock_config_mgr
        self.assertRaises(OSError, self.rollback_mgr._rollback)
        backup.assert_called_once()
        assert t_start.call_count == 1
        assert self.mock_broker.publish_telemetry_response.call_count == 1

    def test_reboot_device(self):
        self.rollback_mgr._reboot_device(Mock())
        self.mock_node_connector.reset_device.assert_called_once()

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('os.path.exists')
    @patch('inbm_vision_lib.timer.Timer.stop')
    def test_stop(self, stop, path_exist, path_isfile, remove_file):
        self.rollback_mgr.stop()
        stop.assert_called_once()
        assert path_exist.call_count == 3
        assert path_isfile.call_count == 3
        assert remove_file.call_count == 3

    def test_is_all_targets_done_return_false(self, ):
        self.assertFalse(self.rollback_mgr.is_all_targets_done("mock_node_1"))

    def test_is_all_targets_done_return_true(self, ):
        self.rollback_mgr.is_all_targets_done("mock_node_1")
        self.assertTrue(self.rollback_mgr.is_all_targets_done("mock_node_2"))
