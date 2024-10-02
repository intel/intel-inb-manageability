import threading
import unittest
from typing import Optional
import os

from ..common.mock_resources import *
from inbm_common_lib.utility import canonicalize_uri
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.sota import SOTA
from dispatcher.sota.sota_error import SotaError
from dispatcher.sota.oras_util import parse_uri
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

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('200', "", 0))
    @patch('json.loads', return_value=mock_resp)
    @patch('requests.get')
    @patch('dispatcher.sota.downloader.read_oras_token', return_value="mock_password")
    @patch('dispatcher.sota.oras_util.verify_source')
    def test_download_successful(self, mock_verify_source, mock_read_token, mock_get, mock_loads, mock_run) -> None:
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
        mock_get.assert_called_once()
        mock_loads.assert_called_once()
        mock_run.assert_called_once()

    def test_parse_uri(self) -> None:
        uri = canonicalize_uri("https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/test/tiberos:latest")
        parsed_uri = parse_uri(uri)
        self.assertEqual(parsed_uri.source, 'https://registry-rs.internal.ledgepark.intel.com/one-intel-edge/test')
        self.assertEqual(parsed_uri.registry_server, 'registry-rs.internal.ledgepark.intel.com')
        self.assertEqual(parsed_uri.image, 'tiberos')
        self.assertEqual(parsed_uri.image_tag, 'latest')
        self.assertEqual(parsed_uri.repository_name, 'one-intel-edge/test')
        self.assertEqual(parsed_uri.image_full_path, 'registry-rs.internal.ledgepark.intel.com/one-intel-edge/test/tiberos:latest')
        self.assertEqual(parsed_uri.registry_manifest, 'https://registry-rs.internal.ledgepark.intel.com/v2/one-intel-edge/test/tiberos/manifests/latest')

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo(CACHE)
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".raw.xz", b"0123456789")
        return mem_repo