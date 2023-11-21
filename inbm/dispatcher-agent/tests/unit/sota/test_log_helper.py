import unittest
import mock

from dispatcher.sota.log_helper import get_log_destination, _is_valid_yes_value, log_command_error
from dispatcher.sota.constants import FILE, CLOUD

from io import StringIO as File


class TestLogHelper(unittest.TestCase):
    def test_succeeds_return_file_when_upgrade_a(self):
        assert (get_log_destination("Y", "upgrade") == 'FILE')

    def test_succeeds_return_file_when_log_to_file(self):
        assert (get_log_destination("Y", "update") == 'FILE')

    def test_succeeds_return_file_when_upgrade_b(self):
        assert (get_log_destination("N", "upgrade") == 'FILE')

    def test_succeeds_return_cloud_when_not_upgrade_and_not_log_to_file(self):
        assert (get_log_destination("N", "update") == 'CLOUD')

    def test_succeeds_return_true_valid_yes(self):
        self.assertTrue(_is_valid_yes_value("Yes"))

    def test_succeeds_return_false_valid_yes(self):
        self.assertFalse(_is_valid_yes_value("No"))

    @mock.patch('dispatcher.sota.log_helper.open')
    def test_succeeds_log_command_error_with_file_destination_read(self, mock_open):
        mock_open.return_value = File('FILE CONTENTS')
        log_command_error(cmd=mock.Mock(), cmd_index=1, err='err', output='output',
                          log_file='file.log', log_destination=FILE,
                          dispatcher_broker=mock.Mock())
        assert mock_open.call_count == 1

    @mock.patch('dispatcher.sota.log_helper.open')
    def test_succeeds_log_command_error_without_file_destination_read(self, mock_open):
        mock_open.return_value = File('FILE CONTENTS')
        log_command_error(cmd=mock.Mock(), cmd_index=1, err='err', output='output',
                          log_file='file.log', log_destination=CLOUD,
                          dispatcher_broker=mock.Mock())
        assert mock_open.call_count == 0
