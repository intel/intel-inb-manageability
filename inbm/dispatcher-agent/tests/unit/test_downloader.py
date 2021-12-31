import os
from unittest import TestCase

from .common.mock_resources import *
from dispatcher.downloader import download
from dispatcher.packagemanager.memory_repo import MemoryRepo
from inbm_lib.xmlhandler import XmlHandler
from dispatcher.dispatcher_exception import DispatcherException
from mock import patch

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestDownloader(TestCase):

    def setUp(self):
        self.mock_dispatcher_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()
        parsed = XmlHandler(fake_ota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.resource = parsed.get_children('ota/type/fota')

    @patch('dispatcher.downloader.is_enough_space_to_download', return_value=True)
    @patch('dispatcher.downloader.get')
    @patch('dispatcher.downloader.verify_source')
    @patch('dispatcher.downloader._check_if_valid_file')
    def test_download_successful(self, mock_check_valid_file, mock_verify_source, mock_fetch, mock_space):
        mock_fetch.return_value = dummy_success
        try:
            download(self.mock_dispatcher_callbacks_obj, mock_url,
                     TestDownloader._build_mock_repo(0), username, password, umask=0)
        except DispatcherException:
            self.fail("Dispatcher download raised DispatcherException unexpectedly!")

    @patch('dispatcher.downloader.verify_source')
    @patch('dispatcher.downloader.is_enough_space_to_download', return_value=False)
    def test_raises_when_space_check_fails(self, mock_verify_source, mock_space):
        with self.assertRaises(DispatcherException):
            download(self.mock_dispatcher_callbacks_obj, mock_url,
                     TestDownloader._build_mock_repo(0),
                     username, password, umask=0)

    @patch('dispatcher.downloader.is_enough_space_to_download', return_value=True)
    @patch('dispatcher.downloader.get')
    @patch('dispatcher.downloader.verify_source', side_effect=DispatcherException('error'))
    def test_raises_when_verify_source_fails(self, mock_verify_source, mock_fetch,
                                             mock_space):
        mock_fetch.return_value = dummy_success
        with self.assertRaises(DispatcherException):
            download(self.mock_dispatcher_callbacks_obj, mock_url,
                     TestDownloader._build_mock_repo(0),
                     username, password, umask=0)
        mock_fetch.assert_not_called()

    @patch('dispatcher.downloader.is_enough_space_to_download', return_value=True)
    @patch('dispatcher.downloader.get')
    @patch('dispatcher.downloader.verify_source')
    def test_raises_when_get_fails(self, mock_verify_source, mock_fetch, mock_space):
        mock_fetch.return_value = dummy_failure
        with self.assertRaises(DispatcherException):
            download(self.mock_dispatcher_callbacks_obj, mock_url,
                     TestDownloader._build_mock_repo(0),
                     username, password, umask=0)
        mock_fetch.assert_called_once()

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
