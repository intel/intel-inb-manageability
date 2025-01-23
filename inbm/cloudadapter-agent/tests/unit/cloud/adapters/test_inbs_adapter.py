"""
Unit tests for the InbsAdapter class
"""

import unittest
from unittest import mock
from unittest.mock import patch, mock_open
import json
from cloudadapter.cloud.adapters.inbs_adapter import InbsAdapter
from cloudadapter.exceptions import AdapterConfigureError


class TestInbsAdapter(unittest.TestCase):

    def setUp(self) -> None:
        # Define a side effect function that returns different data based on the file name
        def read_file_side_effect(file, mode='r', *args, **kwargs):
            if file == '/path/to/valid_token.txt':
                mock_file = mock.mock_open(read_data='token_data').return_value
                mock_file.read.return_value = 'token_data'
                return mock_file
            elif file == '/path/to/valid_cert.pem':
                mock_file = mock.mock_open(read_data='cert_data').return_value
                mock_file.read.return_value = 'cert_data'
                return mock_file
            elif file == '/mnt/udm-luks/onboarding.json':
                onboarding_content = json.dumps({
                    "jwt_token": "sample_jwt_token",
                    "refresh_token": "sample_refresh_token",
                    "node_id": "sample_node_id",
                    "services": [
                        {
                            "type": "INBS",
                            "host": "example.com",
                            "port": "8080"
                        }
                    ]
                })
                mock_file = mock.mock_open(read_data=onboarding_content).return_value
                mock_file.read.return_value = onboarding_content
                return mock_file
            else:
                # Default empty file
                return mock.mock_open(read_data='').return_value

        self.patcher_open = patch('builtins.open', new=mock_open())
        self.mock_open = self.patcher_open.start()
        self.mock_open.side_effect = read_file_side_effect

        self.patcher_exists = patch('os.path.exists', side_effect=lambda x: {
            '/path/to/valid_token.txt': True,
            '/path/to/valid_cert.pem': True,
            '/mnt/udm-luks/onboarding.json': True,
        }.get(x, False))
        self.mock_exists = self.patcher_exists.start()

        self.base_config = {
            "hostname": "localhost",
            "port": "50051",
            "node_id": "node_id",
        }
        self.config_with_token_path_no_tls = {
            **self.base_config,
            "tls_enabled": False,
            "token_path": "/path/to/valid_token.txt"
        }
        self.config_with_tls_cert_path_no_tls = {
            **self.base_config,
            "tls_enabled": False,
            "tls_cert_path": "/path/to/valid_cert.pem"
        }
        self.config_with_tls = {
            **self.base_config,
            "tls_enabled": True,
            "tls_cert_path": "/path/to/valid_cert.pem",
            "token_path": "/path/to/valid_token.txt"
        }
        self.config_without_tls = {
            **self.base_config,
            "tls_enabled": False,
        }
        self.config_with_tls_no_token = {
            **self.base_config,
            "tls_enabled": True,
            "tls_cert_path": "/path/to/valid_cert.pem"
        }
        self.config_with_tls_no_cert = {
            **self.base_config,
            "tls_enabled": True,
            "token_path": "/path/to/valid_token.txt"
        }
        self.config_tls_unspecified = {
            **self.base_config,
        }
        self.config_with_onboarding = {
            "cloud": "inbs",
            "config": {
                "onboarding_json_file": "/mnt/udm-luks/onboarding.json"
            }
        }

    def tearDown(self):
        self.patcher_open.stop()
        self.patcher_exists.stop()

    # Existing Tests
    def test_configure_succeeds_with_valid_token_and_tls(self):
        # Mock the os.path.exists to always return True (e.g., both token and TLS path exist)
        inbs_adapter = InbsAdapter(self.config_with_tls)
        inbs_adapter.configure(self.config_with_tls)
        self.mock_open.assert_any_call('/path/to/valid_token.txt', 'r')
        self.mock_open.assert_any_call('/path/to/valid_cert.pem', 'rb')

    def test_configure_fails_with_invalid_port(self):
        # Ensure the configuration fails when the port is not an integer
        invalid_config = {**self.base_config, "port": "invalid_port"}
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(invalid_config)
            inbs_adapter.configure(invalid_config)

    def test_configure_fails_with_port_out_of_range(self):
        # Ensure the configuration fails when the port is out of range
        invalid_config = {**self.base_config, "port": "65536"}
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(invalid_config)
            inbs_adapter.configure(invalid_config)

    def test_configure_succeeds_with_valid_token_and_no_tls(self):
        # Test configuration without TLS but with a valid token path (token will be ignored)
        adapter = InbsAdapter(self.config_without_tls)
        client = adapter.configure(self.config_without_tls)
        self.mock_open.assert_not_called()

    def test_configure_fails_if_no_tls_options(self):
        # Ensure TLS has to be explicitly disabled to be turned off
        with self.assertRaises(AdapterConfigureError):
            adapter = InbsAdapter(self.config_tls_unspecified)
            adapter.configure(self.config_tls_unspecified)

    def test_configure_fails_if_certificate_given_with_no_tls(self):
        # Ensure the configuration fails if cert is given but TLS is not enabled
        with self.assertRaises(AdapterConfigureError):
            adapter = InbsAdapter(self.config_with_tls_cert_path_no_tls)
            adapter.configure(self.config_with_tls_cert_path_no_tls)

    def test_configure_fails_with_missing_certificate_for_tls(self):
        # Ensure the configuration fails when the TLS cert file does not exist
        with patch('os.path.exists', side_effect=lambda x: x != '/path/to/valid_cert.pem'):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_tls)
                adapter.configure(self.config_with_tls)

    def test_configure_fails_with_missing_token_file(self):
        # Ensure the configuration fails when the token file does not exist
        with patch('os.path.exists', side_effect=lambda x: x != '/path/to/valid_token.txt'):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_tls)
                adapter.configure(self.config_with_tls)

    def test_configure_fails_with_missing_token_for_tls(self):
        # Ensure the configuration fails if TLS is enabled but token is not given
        with self.assertRaises(AdapterConfigureError):
            adapter = InbsAdapter(self.config_with_tls_no_token)
            adapter.configure(self.config_with_tls_no_token)

    def test_configure_fails_with_missing_cert_for_tls(self):
        # Ensure the configuration fails if TLS is enabled but cert is not given
        with self.assertRaises(AdapterConfigureError):
            adapter = InbsAdapter(self.config_with_tls_no_cert)
            adapter.configure(self.config_with_tls_no_cert)

    def test_configure_succeeds_with_onboarding_json_file(self):
        # Test configuration using onboarding_json_file
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "INBS",
                    "host": "example.com",
                    "port": "8080"
                }
            ]
        }):
            adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
            client = adapter.configure(self.config_with_onboarding.get('config', {}))
            self.mock_open.assert_any_call('/mnt/udm-luks/onboarding.json', 'r')
            self.assertTrue(client._tls_enabled)
            self.assertEqual(client._grpc_hostname, "example.com")
            self.assertEqual(client._grpc_port, "8080")
            self.assertEqual(client._client_id, "sample_node_id")
            self.assertEqual(client._token, "sample_jwt_token")
    
    def test_configure_fails_with_onboarding_json_file_and_bad_port(self):
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "INBS",
                    "host": "example.com",
                    "port": "123456789"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                client = adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_missing_onboarding_json_file(self):
        # Ensure the configuration fails when the onboarding_json_file does not exist
        with patch('os.path.exists', side_effect=lambda x: False):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_missing_node_id_in_onboarding(self):
        # Ensure the configuration fails when node_id is missing in onboarding.json
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "services": [
                {
                    "type": "INBS",
                    "host": "example.com",
                    "port": "8080"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_no_inbs_service_in_onboarding(self):
        # Ensure the configuration fails when no INBS service is found in onboarding.json
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "OTHER_SERVICE",
                    "host": "example.com",
                    "port": "8080"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_missing_host_in_inbs_service(self):
        # Ensure the configuration fails when INBS service is missing host
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "INBS",
                    "port": "8080"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_missing_port_in_inbs_service(self):
        # Ensure the configuration fails when INBS service is missing port
        with patch('json.load', return_value={
            "jwt_token": "sample_jwt_token",
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "INBS",
                    "host": "example.com"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))

    def test_configure_fails_with_missing_jwt_token_in_onboarding(self):
        # Ensure the configuration fails when jwt_token is missing in onboarding.json
        with patch('json.load', return_value={
            "refresh_token": "sample_refresh_token",
            "node_id": "sample_node_id",
            "services": [
                {
                    "type": "INBS",
                    "host": "example.com",
                    "port": "8080"
                }
            ]
        }):
            with self.assertRaises(AdapterConfigureError):
                adapter = InbsAdapter(self.config_with_onboarding.get('config', {}))
                adapter.configure(self.config_with_onboarding.get('config', {}))


if __name__ == '__main__':
    unittest.main()
