import threading
import unittest
import tempfile
import os
import shutil

from ..common.mock_resources import *
from inbm_common_lib.utility import canonicalize_uri
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.sota import SOTA
from dispatcher.sota.sota_error import SotaError
from dispatcher.sota.tiber_util import read_release_server_token
from dispatcher.constants import CACHE
from inbm_lib.xmlhandler import XmlHandler
from unittest.mock import patch, MagicMock

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')
mock_resp = {
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.intel.ensp.file",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:cededd06f9724b1fe11ccc25ffc32a13f4de27ffb445485535ef33e0ef502665",
      "size": 467524352,
      "annotations": {
        "org.opencontainers.image.title": "core-2.0.20240830.0156.raw.xz"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar",
      "digest": "sha256:67738846a2d1235ffdcb942cc5529f78b5d816910c55b6647614f9e70f21f3d0",
      "size": 109,
      "annotations": {
        "org.opencontainers.image.title": "core-2.0.20240830.0156.raw.xz.sha256sum"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2024-08-30T07:34:34Z"
  }
}

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
                           'signature': "mock_signature", 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestDownloader._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'download-only', 'package_list': '',
                           'deviceReboot': "no"}
        cls.sota_instance = SOTA(parsed_manifest,
                                 "remote",
                                 MockDispatcherBroker.build_mock_dispatcher_broker(),
                                 UpdateLogger("SOTA", "metadata"),
                                 None,
                                 install_check_service=MockInstallCheckService(),
                                 cancel_event=threading.Event())
        cls.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('tiber')

    @patch('requests.get')
    @patch('dispatcher.sota.downloader.read_release_server_token', return_value="mock_password")
    @patch('dispatcher.sota.tiber_util.verify_source')
    def test_download_successful(self, mock_verify_source, mock_read_token, mock_get) -> None:
        self.release_date = self.username = self.password = None
        mock_url = canonicalize_uri("https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/tiberos:latest")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        assert TestDownloader.sota_instance
        TestDownloader.sota_instance.factory = SotaOsFactory(
            MockDispatcherBroker.build_mock_dispatcher_broker(), None, []).get_os('tiber')
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

        mock_verify_source.assert_called_once()
        mock_read_token.assert_called_once()
        assert mock_get.call_count == 2

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo(CACHE)
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".raw.xz", b"0123456789")
        return mem_repo

    def test_read_release_server_token_successful(self) -> None:
        directory = tempfile.mkdtemp()
        try:
            repo = DirectoryRepo(directory)
            repo.add("rs_access_token", b"mock_token123")
            token = read_release_server_token(token_path=os.path.join(directory, "rs_access_token"))
        finally:
            shutil.rmtree(directory)

        self.assertEqual(token, "mock_token123")

    def test_read_release_server_token_failed_with_fake_path(self) -> None:
        with self.assertRaises(SotaError):
            read_release_server_token(token_path="/fake/path/rs_access_token")
