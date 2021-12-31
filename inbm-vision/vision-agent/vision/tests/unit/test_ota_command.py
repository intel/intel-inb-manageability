from unittest import TestCase
from mock import Mock

from vision.command.ota_command import *


class TestReceiveRequestDownloadResponse(TestCase):

    def test_execute_with_response_True(self):
        mock_updater = Mock()
        mock_updater.update_download_request_status
        mock_response = {'sendDownload': 'True'}
        command = ReceiveRequestDownloadResponse('123ABC', mock_updater, mock_response)
        command.execute()
        mock_updater.update_download_request_status.assert_called_once()

    def test_execute_with_response_False(self):
        mock_updater = Mock()
        mock_updater.update_download_request_status
        mock_response = {'sendDownload': 'False'}
        command = ReceiveRequestDownloadResponse('123ABC', mock_updater, mock_response)
        command.execute()
        mock_updater.update_download_request_status.assert_called_once()


class TestSendFileCommand(TestCase):

    def setUp(self):
        self.mock_xlink_manager = Mock()
        self.mock_xlink_manager.send_file
        ota_filename = 'BIOSX41.tar'
        self.Command = SendFileCommand('123ABC', self.mock_xlink_manager, ota_filename)

    def test_execute(self):
        self.Command.execute()
        self.mock_xlink_manager.send_file.assert_called_once()


class TestUpdateNodeCommand(TestCase):

    def setUp(self):
        self.mock_updater = Mock()
        self.mock_updater.send_request_to_send_file
        self.Command = UpdateNodeCommand(self.mock_updater)

    def test_execute(self):
        self.Command.execute()
        self.mock_updater.send_request_to_send_file.assert_called_once()
