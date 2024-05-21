"""
Unit tests for the cloud_builders module


"""


from cloudadapter.cloud.cloud_builders import build_client_with_config, _configure_tls
from cloudadapter.exceptions import ClientBuildError
import jsonschema

import unittest
import mock


class TestCloudBuilders(unittest.TestCase):

    def setUp(self) -> None:
        self.CONFIG = {
            "mqtt": {
                "username": "username",
                "password": "password",
                "hostname": "hostname",
                "port": 1234,
                "client_id": "client_id"
            },
            "tls": {
                "version": "TLSv1.2",
            },
            "proxy": {
                "auto": True
            },
            "event": {
                "pub": "event_pub",
                "format": "event_format"
            },
            "telemetry": {
                "pub": "telemetry_pub",
                "format": "telemetry_format"
            },
            "attribute": {
                "pub": "attribute_pub",
                "format": "attribute_formate"
            },
            "command": {
                "pub": "manageability/request/command",
                "format": "{ \"ts\": \"{ts}\", \"values\": {\"command\": \"{value}\"}}"
            },
            "method": {
                "pub": "response_pub",
                "format": "response_format",
                "sub": "method_sub",
                "parse": {
                    "single": {
                        "method": {
                            "path": "method/path"
                        },
                        "args": {
                            "path": "args/path"
                        }
                    }
                }
            },
            "echoers": [{
                "pub": "echo_pub",
                "format": "echo_format",
                "sub": "echo_sub",
            }]
        }

        self.X509_CONFIG = {
            "mqtt": {
                "username": "username",
                "hostname": "hostname",
                "port": 1234,
                "client_id": "client_id"
            },
            "tls": {
                "version": "TLSv1.1",
            },
            "x509": {
                "device_cert": "device_cert",
                "device_key": "device_key",
            },
            "proxy": {
                "auto": True
            },
            "event": {
                "pub": "event_pub",
                "format": "event_format"
            },
            "command": {
                "pub": "manageability/request/command",
                "format": "{ \"ts\": \"{ts}\", \"values\": {\"command\": \"{value}\"}}"
            },
            "telemetry": {
                "pub": "telemetry_pub",
                "format": "telemetry_format"
            },
            "attribute": {
                "pub": "attribute_pub",
                "format": "attribute_formate"
            },
            "method": {
                "pub": "response_pub",
                "format": "response_format",
                "sub": "method_sub",
                "parse": {
                    "single": {
                        "method": {
                            "path": "method/path"
                        },
                        "args": {
                            "path": "args/path"
                        }
                    }
                }
            },
            "echoers": [{
                "pub": "echo_pub",
                "format": "echo_format",
                "sub": "echo_sub",
            }]
        }

    def test_configure_tls_raises_error_on_symlink(self) -> None:
        config = {
            "tls": {
                "certificates": "fake_ca_certs"
            },
            "x509": {
                "device_cert": "fake_device_cert",
                "device_key": "fake_device_key"
            }
        }

        with mock.patch("os.path.islink", return_value=True):
            with self.assertRaises(ClientBuildError) as context:
                _configure_tls(config)
            self.assertIn("ca_certs (fake_ca_certs) should not be a symlink",
                          str(context.exception))

            config["tls"]["certificates"] = None
            with self.assertRaises(ClientBuildError) as context:
                _configure_tls(config)
            self.assertIn("device_cert (fake_device_cert) should not be a symlink",
                          str(context.exception))

            config["x509"]["device_cert"] = None
            with self.assertRaises(ClientBuildError) as context:
                _configure_tls(config)
            self.assertIn("device_key (fake_device_key) should not be a symlink",
                          str(context.exception))

    @mock.patch('cloudadapter.cloud.cloud_builders.CloudClient', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_config_succeeds(
            self, mock_validate_config, MockMQTTConnection, MockCloudClient) -> None:
        mock_validate_config.return_value = None
        client = build_client_with_config(self.CONFIG)
        assert client is MockCloudClient.return_value

    @mock.patch('cloudadapter.cloud.cloud_builders.CloudClient', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_config_no_command_succeeds(
            self, mock_validate_config, MockMQTTConnection, MockCloudClient) -> None:
        mock_validate_config.return_value = None
        no_command_config = self.CONFIG
        del no_command_config['command']
        client = build_client_with_config(no_command_config)
        assert client is MockCloudClient.return_value

    @mock.patch('cloudadapter.cloud.cloud_builders.CloudClient', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    @mock.patch('cloudadapter.cloud.client.utilities.SSLContext.load_cert_chain', autospec=True)
    def test_build_client_with_x509_config_succeeds(
            self, mock_load_certs, mock_validate_config, MockMQTTConnection, MockCloudClient) -> None:
        mock_validate_config.return_value = None
        client = build_client_with_config(self.X509_CONFIG)
        assert client is MockCloudClient.return_value

    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_config_fails(self, mock_validate_config, MockMQTTConnection) -> None:
        mock_validate_config.side_effect = jsonschema.ValidationError("Error!")
        failed = False
        try:
            build_client_with_config(self.CONFIG)
        except ClientBuildError:
            failed = True
        assert failed

    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_x509_config_fails(self, mock_validate_config, MockMQTTConnection) -> None:
        mock_validate_config.side_effect = jsonschema.ValidationError("Error!")
        failed = False
        try:
            build_client_with_config(self.X509_CONFIG)
        except ClientBuildError:
            failed = True
        assert failed

    @mock.patch('cloudadapter.cloud.cloud_builders.TLSConfig', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_tls_fails(
            self, mock_validate_config, MockMQTTConnection, MockTLSConfig) -> None:
        MockTLSConfig.side_effect = IOError("Error!")
        failed = False
        try:
            build_client_with_config(self.CONFIG)
        except ClientBuildError:
            failed = True
        assert failed
