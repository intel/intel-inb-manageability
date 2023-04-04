"""
Unit tests for the cloud_builders module


"""


from cloudadapter.cloud.cloud_builders import build_client_with_config
from cloudadapter.exceptions import ClientBuildError
from ssl import SSLContext
import jsonschema

import unittest
import mock


class TestCloudBuilders(unittest.TestCase):

    def setUp(self):
        self.CONFIG = {
            "mqtt": {
                "username": "username",
                "password": "password",
                "hostname": "hostname",
                "port": 1234,
                "client_id": "client_id"
            },
            "tls": {
                "version": "TLSv1.2"
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
                "version": "TLSv1.1"
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

    @mock.patch('cloudadapter.cloud.cloud_builders.CloudClient', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_config_succeeds(
            self, mock_validate_config, MockMQTTConnection, MockCloudClient):
        mock_validate_config.return_value = None
        client = build_client_with_config(self.CONFIG)
        assert client is MockCloudClient.return_value

    @mock.patch('cloudadapter.cloud.cloud_builders.CloudClient', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    @mock.patch('cloudadapter.cloud.client.utilities.SSLContext.load_cert_chain', autospec=True)
    def test_build_client_with_x509_config_succeeds(
            self, mock_load_certs, mock_validate_config, MockMQTTConnection, MockCloudClient):
        mock_validate_config.return_value = None
        client = build_client_with_config(self.X509_CONFIG)
        assert client is MockCloudClient.return_value

    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_config_fails(self, mock_validate_config, MockMQTTConnection):
        mock_validate_config.side_effect = jsonschema.ValidationError("Error!")
        failed = False
        try:
            build_client_with_config(self.CONFIG)
        except ClientBuildError:
            failed = True
        assert failed

    @mock.patch('cloudadapter.cloud.cloud_builders.MQTTConnection', autospec=True)
    @mock.patch('cloudadapter.cloud.cloud_builders.validate_config', autospec=True)
    def test_build_client_with_x509_config_fails(self, mock_validate_config, MockMQTTConnection):
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
            self, mock_validate_config, MockMQTTConnection, MockTLSConfig):
        MockTLSConfig.side_effect = IOError("Error!")
        failed = False
        try:
            build_client_with_config(self.CONFIG)
        except ClientBuildError:
            failed = True
        assert failed
