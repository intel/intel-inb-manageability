import unittest
import tempfile
import shutil
from typing import Optional
import os
import hashlib

from ..common.mock_resources import *
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.downloader import TiberOSDownloader
from dispatcher.sota.sota import SOTA
from dispatcher.sota.sota_error import SotaError
from inbm_lib.xmlhandler import XmlHandler
from inbm_lib.constants import CACHE
from unittest.mock import patch

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestDownloader(unittest.TestCase):
    sota_instance: Optional[SOTA] = None
    resource = {'': ''}
    mock_disp_broker: DispatcherBroker = MockDispatcherBroker.build_mock_dispatcher_broker()
    sotaerror_instance: Optional[SotaError] = None

    @classmethod
    def setUp(cls) -> None:
        cls.sotaerror_instance = SotaError(cls.mock_disp_broker)

        assert cls.mock_disp_broker is not None
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'signature': None, 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestDownloader._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'no-download', 'package_list': '',
                           'deviceReboot': "no"}
        cls.sota_instance = SOTA(parsed_manifest,
                                 "remote",
                                 MockDispatcherBroker.build_mock_dispatcher_broker(),
                                 UpdateLogger("SOTA", "metadata"),
                                 None,
                                 install_check_service=MockInstallCheckService())
        cls.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('YoctoX86_64')

    @patch('dispatcher.sota.downloader.Downloader.is_valid_release_date', return_value=True)
    @patch('dispatcher.sota.downloader.YoctoDownloader.download')
    def test_download_successful(self, mock_download, mock_date) -> None:
        self.release_date = self.username = self.password = None

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_broker,
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
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_broker,
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
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('YoctoX86_64')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert installer
        try:
            installer.download(self.mock_disp_broker, mock_url,
                               TestDownloader._build_mock_repo(
                                   0),
                               self.username, self.password, self.release_date)
        except SotaError as e:
            self.assertEqual(str(e), 'Missing manifest Release date field')

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo

    @patch('dispatcher.sota.downloader.read_oras_token', return_value="mock_password")
    @patch('dispatcher.sota.downloader.oras_download')
    def test_tiberos_download_successful(self, mock_download, mock_read_token) -> None:
        self.release_date = self.username = None
        password = "mock_password"
        mock_url = canonicalize_uri("https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/tiberos:latest")

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('TiberOS')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert isinstance(installer, TiberOSDownloader)

        directory = tempfile.mkdtemp()
        try:
            repo = DirectoryRepo(directory)

            repo.add("test", b"This is a test file.")

            # Calculate the SHA256 checksum
            sha256_hash = hashlib.sha256()
            with open(os.path.join(directory, "test"), 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b''):
                    sha256_hash.update(chunk)
            checksum = sha256_hash.hexdigest()
            installer._signature = checksum
            try:
                installer.download(self.mock_disp_broker,
                                   mock_url, repo,
                                   self.username, password, self.release_date)
            except (SotaError, DispatcherException):
                self.fail("raised Error unexpectedly!")
        finally:
            shutil.rmtree(directory)

        mock_read_token.assert_called_once()
        mock_download.assert_called_once()

    @patch('dispatcher.sota.downloader.read_oras_token', return_value="mock_password")
    @patch('dispatcher.sota.downloader.oras_download')
    def test_tiberos_download_and_signature_failed(self, mock_download, mock_read_token) -> None:
        self.release_date = self.username = None
        password = "mock_password"
        mock_url = canonicalize_uri("https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/tiberos:latest")

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('TiberOS')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert isinstance(installer, TiberOSDownloader)

        directory = tempfile.mkdtemp()
        try:
            repo = DirectoryRepo(directory)

            repo.add("test", b"This is a test file.")

            installer._signature = "invalid checksum"
            with self.assertRaises(SotaError):
                installer.download(self.mock_disp_broker,
                                   mock_url, repo,
                                   self.username, password, self.release_date)
        finally:
            shutil.rmtree(directory)

        mock_read_token.assert_called_once()
        mock_download.assert_called_once()

    def test_tiberos_download_with_empty_uri(self) -> None:
        self.release_date = self.username = None
        password = "mock_password"
        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('TiberOS')
        factory = TestDownloader.sota_instance.factory
        assert factory
        installer = factory.create_downloader()
        assert isinstance(installer, TiberOSDownloader)

        directory = tempfile.mkdtemp()
        try:
            repo = DirectoryRepo(directory)

            installer._signature = "invalid checksum"
            with self.assertRaises(SotaError):
                installer.download(self.mock_disp_broker,
                                   None, repo,
                                   self.username, password, self.release_date)
        finally:
            shutil.rmtree(directory)
