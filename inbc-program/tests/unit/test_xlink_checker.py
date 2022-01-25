from unittest import TestCase
from inbc.xlink_checker import XlinkChecker
from mock import Mock, patch


class TestXlinkChecker(TestCase):

    @patch('inbm_vision_lib.timer.Timer.start')
    def test_create_xlink_checker_success(self, t_start):
        def mock_callback():
            pass
        XlinkChecker(mock_callback)
        t_start.assert_called_once()

    @patch('inbc.xlink_checker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_return_error_dev_off(self, t_start, mock_logger):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.return_error(0)
        assert mock_logger.error.call_count == 4

    @patch('inbc.xlink_checker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_return_error_driver_not_found(self, t_start, mock_logger):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.return_error(5)
        assert mock_logger.error.call_count == 4

    @patch('inbm_vision_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbc.xlink_checker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_return_error_dev_busy(self, t_start, mock_logger, mock_reconnect):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.return_error(2)
        assert mock_logger.error.call_count == 2

    @patch('inbc.xlink_checker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_return_error_dev_recovery(self, t_start, mock_logger):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.return_error(3)
        assert mock_logger.error.call_count == 2

    @patch('inbc.xlink_checker.logger')
    @patch('inbm_vision_lib.timer.Timer.start')
    def test_return_error_dev_error(self, t_start, mock_logger):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.return_error(1)
        assert mock_logger.error.call_count == 2

    @patch('inbm_vision_lib.timer.Timer.start')
    def test_update_device_status(self, t_start):
        mock_callback = Mock()
        xlink_checker = XlinkChecker(mock_callback)
        xlink_checker.update_device_status("17022525-4")
        self.assertEqual(len(xlink_checker._device_list), 1)
