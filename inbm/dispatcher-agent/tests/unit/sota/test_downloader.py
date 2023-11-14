import unittest
from typing import Optional
import os

from ..common.mock_resources import *
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.sota import SOTA
from dispatcher.sota.sota_error import SotaError
from inbm_lib.xmlhandler import XmlHandler
from mock import patch

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestDownloader(unittest.TestCase):
    sota_instance: Optional[SOTA] = None
    resource = {'': ''}
    mock_disp_callbacks_obj: DispatcherCallbacks = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()
    sotaerror_instance: Optional[SotaError] = None

    @classmethod
    def setUp(cls):
        cls.sotaerror_instance = SotaError(cls.mock_disp_callbacks_obj)

        assert cls.mock_disp_callbacks_obj is not None
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'callback': cls.mock_disp_callbacks_obj, 'signature': None, 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestDownloader._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'no-download', 'deviceReboot': "no"}
        cls.sota_instance = SOTA(parsed_manifest, "remote",
                                 DispatcherCallbacks(broker_core=MockDispatcherBroker.build_mock_dispatcher_broker(),
                                                     proceed_without_rollback=cls.mock_disp_callbacks_obj.proceed_without_rollback,
                                                     logger=cls.mock_disp_callbacks_obj.logger),
                                 None,
                                 install_check_service=MockInstallCheckService())
        cls.sota_instance.factory = SotaOsFactory(
            cls.mock_disp_callbacks_obj, None).get_os('YoctoX86_64')

    @patch('dispatcher.sota.downloader.Downloader.is_valid_release_date', return_value=True)
    @patch('dispatcher.sota.downloader.YoctoDownloader.download')
    def test_download_successful(self, mock_download, mock_date) -> None:
        self.release_date = self.username = self.password = None

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            TestDownloader.mock_disp_callbacks_obj, None).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_callbacks_obj,
                               mock_url, TestDownloader._build_mock_repo(0),
                               self.username, self.password, self.release_date)
        except (SotaError, DispatcherException):
            self.fail("raised Error unexpectedly!")

        mock_download.assert_called_once()

    @patch('dispatcher.sota.downloader.Downloader.is_valid_release_date', return_value=True)
    @patch('dispatcher.sota.downloader.YoctoDownloader.download', side_effect=DispatcherException('foo'))
    def test_download_raises(self, mock_download, mock_date) -> None:
        self.release_date = self.username = self.password = None

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            TestDownloader.mock_disp_callbacks_obj, None).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_callbacks_obj,
                               mock_url, TestDownloader._build_mock_repo(0),
                               self.username, self.password, self.release_date)
        except DispatcherException as e:
            self.assertRaises(DispatcherException)
            self.assertEqual(str(e), "foo")

        mock_download.assert_called_once()

    def test_return_false_when_is_valid_release_date_fails(self) -> None:
        self.release_date = self.username = self.password = None
        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            TestDownloader.mock_disp_callbacks_obj, None).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_callbacks_obj, mock_url,
                               TestDownloader._build_mock_repo(
                                   0),
                               self.username, self.password, self.release_date)
        except SotaError as e:
            self.assertEquals(str(e), 'Missing manifest Release date field')

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
