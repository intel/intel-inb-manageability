"""
Unit tests for the InbsAdapter class
"""

import unittest
from mock import patch, mock
from cloudadapter.cloud.adapters.inbs_adapter import InbsAdapter
from cloudadapter.exceptions import AdapterConfigureError


class TestInbsAdapter(unittest.TestCase):

    def setUp(self) -> None:
        # Define a side effect function that returns different data based on the file name
        def read_file_side_effect(*args, **kwargs):
            if args[0] == '/path/to/valid_token.txt':
                return mock.mock_open(read_data='token_data').return_value
            elif args[0] == '/path/to/valid_cert.pem':
                return mock.mock_open(read_data='cert_data').return_value
            else:
                return mock.mock_open(read_data='').return_value

        self.patcher_open = patch('builtins.open', side_effect=read_file_side_effect)
        self.mock_open = self.patcher_open.start()

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

    def tearDown(self):
        self.patcher_open.stop()

    def test_configure_succeeds_with_valid_token_and_tls(self):

        # Mock the os.path.exists to always return True (e.g., both token and TLS path exist)
        with patch('os.path.exists', return_value=True):
            inbs_adapter = InbsAdapter(self.config_with_tls)
            self.mock_open.assert_has_calls([mock.call('/path/to/valid_token.txt', 'r'),
                                             mock.call('/path/to/valid_cert.pem', 'rb')],
                                            any_order=True)

    def test_configure_fails_with_invalid_port(self):
        # Ensure the configuration fails when the port is not an integer
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter({**self.base_config, "port": "invalid_port"})

    def test_configure_fails_with_port_out_of_range(self):
        # Ensure the configuration fails when the port is out of range
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter({**self.base_config, "port": "65536"})

    def test_configure_succeeds_with_valid_token_and_no_tls(self):
        # Test configuration without TLS but with a valid token path (token will be ignored)
        with patch('os.path.exists', return_value=True):
            inbs_adapter = InbsAdapter(self.config_without_tls)
            self.mock_open.assert_not_called()

    def test_configure_fails_if_token_given_with_no_tls(self):
        # Ensure the configuration fails if token is given but TLS is not enabled
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(self.config_with_token_path_no_tls)
    
    def test_configure_fails_if_no_tls_options(self):
        # Ensure TLS has to be explicitly disabled to be turned off
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(self.config_tls_unspecified)

    def test_configure_fails_if_certificate_given_with_no_tls(self):
        # Ensure the configuration fails if cert is given but TLS is not enabled
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(self.config_with_tls_cert_path_no_tls)

    def test_configure_fails_with_missing_certificate_for_tls(self):
        # Ensure the configuration fails when the TLS cert file does not exist
        with patch('os.path.exists', side_effect=lambda x: x != '/path/to/valid_cert.pem'):
            with self.assertRaises(AdapterConfigureError):
                inbs_adapter = InbsAdapter(self.config_with_tls)

    def test_configure_fails_with_missing_token_file(self):
        # Ensure the configuration fails when the token file does not exist
        with patch('os.path.exists', side_effect=lambda x: x != '/path/to/valid_token.txt'):
            with self.assertRaises(AdapterConfigureError):
                inbs_adapter = InbsAdapter(self.config_with_tls)

    def test_configure_fails_with_missing_token_for_tls(self):
        # Ensure the configuration fails if TLS is enabled but token is not given
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(self.config_with_tls_no_token)

    def test_configure_fails_with_missing_cert_for_tls(self):
        # Ensure the configuration fails if TLS is enabled but cert is not given
        with self.assertRaises(AdapterConfigureError):
            inbs_adapter = InbsAdapter(self.config_with_tls_no_cert)
