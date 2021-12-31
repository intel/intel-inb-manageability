"""
Unit tests for the TelitAdapter class


"""


import unittest
import mock

from cloudadapter.exceptions import AdapterConfigureError, ClientBuildError
from cloudadapter.cloud.adapters.telit_adapter import TelitAdapter


class TestTelitAdapter(unittest.TestCase):

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.telit_adapter.build_client_with_config', autospec=True)
    def setUp(self, mock_build_client_with_config, MockCloudClient):
        self.MockCloudClient = MockCloudClient
        self.mocked_client = self.MockCloudClient.return_value
        mock_build_client_with_config.return_value = self.mocked_client

        self.CONFIG = {
            "hostname": "hostname",
            "port": 1234,
            "key": "key",
            "token": "token"
        }
        self.telit_adapter = TelitAdapter(self.CONFIG)
        self.telit_adapter.configure(self.CONFIG)

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.telit_adapter.build_client_with_config', autospec=True)
    def test_configure_succeeds(self, mock_build_client_with_config, MockCloudClient):
        mock_build_client_with_config.return_value = self.mocked_client
        self.telit_adapter.configure(self.CONFIG)
        assert mock_build_client_with_config.call_count == 1

    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient')
    @mock.patch(
        'cloudadapter.cloud.adapters.telit_adapter.build_client_with_config')
    def test_configure_with_build_fail_fails(self, mock_build_client_with_config, MockCloudClient):
        mock_build_client_with_config.return_value = self.mocked_client
        mock_build_client_with_config.side_effect = ClientBuildError("Error!")

        with self.assertRaises(AdapterConfigureError):
            self.telit_adapter.configure(self.CONFIG)

    def test_parse_payload(self):
        ota_payload = {
            'vv_username': 'username',
            'vw_password': 'password',
            'vx_docker_registry': 'dockerRegistry',
            'vy_docker_username': 'dockerUsername',
            'vz_docker_password': 'dockerPassword'
        }
        parsed_payload = {
            'username': 'username',
            'password': 'password',
            'dockerRegistry': 'dockerRegistry',
            'dockerUsername': 'dockerUsername',
            'dockerPassword': 'dockerPassword'
        }
        self.assertEquals(parsed_payload, self.telit_adapter._parse_payload(ota_payload))
