from unittest import TestCase

from unit.common.mock_resources import *
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.aota.aota_error import AotaError
from dispatcher.ota_downloader import AotaDownloader, SotaDownloader, FotaDownloader
from dispatcher.packagemanager.memory_repo import MemoryRepo
from mock import patch

ota_element = {'fetch': 'https://abc.tar'}
parsed_manifest = {'uri': 'https://abc.com', 'signature': 'asdf',
                   'hash_algorithm': '3',
                   'resource': ota_element,
                   'username': 'uname',
                   'password': 'pwd'}


class TestOtaDownloader(TestCase):

    def setUp(self):
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()
        self.mock_disp_broker = MockDispatcherBroker.build_mock_dispatcher_broker()

    def test_download_aota(self):
        try:
            AotaDownloader(parsed_manifest).download()
        except (DispatcherException, AotaError):
            self.fail("Raised expected when not expected.")

    def test_download_sota(self):
        try:
            SotaDownloader(parsed_manifest).download()
        except (DispatcherException, AotaError):
            self.fail("Raised expected when not expected.")

    @patch('dispatcher.ota_downloader.download')
    def test_download_fota(self, mock_download):
        try:
            FotaDownloader(self.mock_disp_broker, parsed_manifest).download()
        except (DispatcherException, AotaError):
            self.fail("Raised expected when not expected.")
