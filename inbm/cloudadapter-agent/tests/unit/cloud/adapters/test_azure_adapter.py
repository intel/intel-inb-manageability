"""
Unit tests for the AzureAdapter class


"""
import json
import unittest
import mock
from unittest.mock import MagicMock

from cloudadapter.exceptions import AdapterConfigureError, ClientBuildError
from cloudadapter.cloud.adapters.azure_adapter import AzureAdapter
from time import time

#class TestAzureAdapterFailures(unittest.TestCase):
    # @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.put')
    # @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.get')
    # def test_configure_json_decode_error(self, mock_get, mock_put):
    #     # Set up the AzureAdapter with some dummy configs
    #     configs = {
    #         "scope_id": "test_scope_id",
    #         "device_id": "test_device_id",
    #         "device_sas_key": "test_device_sas_key"
    #     }
    #     adapter = AzureAdapter(configs)
        
    #     # Mock the put request to return a response with invalid JSON content
    #     mock_put_response = MagicMock()
    #     mock_put_response.ok = True
    #     mock_put_response.text = "Invalid JSON"
    #     mock_put.return_value = mock_put_response

    #     # Mock the get request to return a response with valid JSON content
    #     # This is necessary because the configure method may call get after put
    #     mock_get_response = MagicMock()
    #     mock_get_response.ok = True
    #     mock_get_response.text = json.dumps({"status": "assigned", "registrationState": {"assignedHub": "test_hub"}})
    #     mock_get.return_value = mock_get_response
        
    #     with self.assertRaises(AdapterConfigureError) as context:
    #         adapter.configure(configs)

    #     # Check that the exception message contains the expected text
    #     self.assertIn("Error retrieving hostname", str(context.exception))

class TestAzureAdapter(unittest.TestCase):

    @mock.patch.object(AzureAdapter, '_retrieve_hostname', autospec=True)
    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.azure_adapter.build_client_with_config', autospec=True)
    def setUp(self, mock_build_client_with_config, MockCloudClient, _mock_retrieve_hostname) -> None:
        self.MockCloudClient = MockCloudClient
        self.mocked_client = self.MockCloudClient.return_value
        mock_build_client_with_config.return_value = self.mocked_client

        self._mock_retrieve_hostname = _mock_retrieve_hostname
        self._mock_retrieve_hostname.return_value = "HOSTNAME"

        self.CONFIG = {
            "scope_id": "SCOPE-ID",
            "device_id": "DEVICE-ID",
            "device_sas_key": "",
            "device_certs": "ADEVICECERT==",
            "device_key": "ADEVICEKEY=="
        }
        self.SAS_CONFIG = {
            "scope_id": "SCOPE-ID",
            "device_id": "DEVICE-ID",
            "device_sas_key": "sasKey",
            "device_certs": "",
            "device_key": ""
        }
        self.CONFIG_WITHOUT_SCOPE_ID = {
            "device_id": "DEVICE-ID",
            "device_sas_key": "sasKey",
            "device_certs": "",
            "device_key": ""
        }

        self.azure_adapter = AzureAdapter(self.CONFIG)
        self.azure_adapter.configure(self.CONFIG)

    @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.put')
    @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.get')
    def test_configure_json_decode_error(self, mock_get, mock_put):       
        # Mock the put request to return a response with invalid JSON content
        mock_put_response = MagicMock()
        mock_put_response.ok = True
        mock_put_response.text = "Invalid JSON"
        mock_put.return_value = mock_put_response

        # Mock the get request to return a response with valid JSON content
        # This is necessary because the configure method may call get after put
        mock_get_response = MagicMock()
        mock_get_response.ok = True
        mock_get_response.text = json.dumps({"status": "assigned", "registrationState": {"assignedHub": "test_hub"}})
        mock_get.return_value = mock_get_response
        
        with self.assertRaises(AdapterConfigureError) as context:
            self.azure_adapter.configure(self.CONFIG)

        # Check that the exception message contains the expected text
        self.assertIn("Error retrieving hostname", str(context.exception))
        
    @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.put')
    @mock.patch('cloudadapter.cloud.adapters.azure_adapter.requests.get')
    def test_retrieve_hostname_while_loop(self, mock_get, mock_put):
        # Mock the put request to return a response indicating the device is being assigned
        assigning_response = {
            "status": "assigning",
            "operationId": "test_operation_id"
        }
        mock_put_response = MagicMock()
        mock_put_response.ok = True
        mock_put_response.text = json.dumps(assigning_response)
        mock_put.return_value = mock_put_response

        # Mock the get request to return "assigning" status twice, then "assigned"
        assigning_get_response = MagicMock()
        assigning_get_response.ok = True
        assigning_get_response.text = json.dumps(assigning_response)
        
        assigned_response = {
            "status": "assigned",
            "registrationState": {"assignedHub": "test_hub"}
        }
        assigned_get_response = MagicMock()
        assigned_get_response.ok = True
        assigned_get_response.text = json.dumps(assigned_response)
        
         # Set up the side_effect for the get mock to return "assigning" twice, then "assigned"
        mock_get.side_effect = [assigning_get_response, assigning_get_response, assigned_get_response]

        # Call the _retrieve_hostname method
        hostname = self.azure_adapter._retrieve_hostname(self.CONFIG['scope_id'], self.CONFIG['device_id'], {'sas_key': self.CONFIG['device_sas_key']}, None)

        # Assert that the hostname is as expected
        self.assertEqual(hostname, "test_hub")

        # Assert that the get request was called three times
        self.assertEqual(mock_get.call_count, 3)
    
    @mock.patch.object(AzureAdapter, '_retrieve_hostname', autospec=True)
    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.azure_adapter.build_client_with_config', autospec=True)
    def test_configure_succeeds(
            self, mock_build_client_with_config, MockCloudClient, _mock_retrieve_hostname) -> None:
        mock_build_client_with_config.return_value = self.mocked_client
        self.azure_adapter.configure(self.CONFIG)
        assert mock_build_client_with_config.call_count == 1

    @mock.patch.object(AzureAdapter, '_retrieve_hostname', autospec=True)
    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.azure_adapter.build_client_with_config', autospec=True)
    @mock.patch('cloudadapter.cloud.adapters.azure_adapter.AzureAdapter._generate_sas_token', autospec=True)
    def test_sas_configure_succeeds(
            self, mock_get_sas_token, mock_build_client_with_config, MockCloudClient, _mock_retrieve_hostname) -> None:
        mock_build_client_with_config.return_value = self.mocked_client
        self.azure_adapter.configure(self.SAS_CONFIG)
        assert mock_get_sas_token.call_count == 1
        assert mock_build_client_with_config.call_count == 1
            
    @mock.patch('base64.b64encode', autospec=True)
    @mock.patch('future.moves.urllib.request.quote', autospec=True)
    def test_generate_sas_token(self, mock_quote, mock_base64encode) -> None:
        res = self.azure_adapter._generate_sas_token('registration', 'sas_token=', int(time()))
        self.assertRegex(res, "SharedAccessSignature")

    @mock.patch('json.loads')
    @mock.patch('requests.put')
    def test_get_hostname(self, mock_put_request, mock_json_load) -> None:
        # mock the response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_put_request.put.return_value = mock_response

        mock_json_load.return_value = dict({"registrationState": {"assignedHub": "portland"}})

        device_auth_set = {"certs": "certs", "sas_key": "device_sas_key"}
        res = self.azure_adapter._retrieve_hostname("scope", "device_id", device_auth_set, None)
        self.assertEqual(res, "portland")

    @mock.patch.object(AzureAdapter, '_retrieve_hostname', autospec=True)
    @mock.patch('cloudadapter.cloud.client.cloud_client.CloudClient', autospec=True)
    @mock.patch(
        'cloudadapter.cloud.adapters.azure_adapter.build_client_with_config', autospec=True)
    def test_configure_with_build_fail_fails(self, mock_build_client_with_config, MockCloudClient, mock_retrieve_hostname) -> None:
        mock_build_client_with_config.return_value = self.mocked_client
        mock_build_client_with_config.side_effect = ClientBuildError("Error!")

        with self.assertRaises(AdapterConfigureError):
            self.azure_adapter.configure(self.CONFIG)

    def test_configure_without_scope_id_fail(self) -> None:
        with self.assertRaises(AdapterConfigureError):
            self.azure_adapter.configure(self.CONFIG_WITHOUT_SCOPE_ID)
