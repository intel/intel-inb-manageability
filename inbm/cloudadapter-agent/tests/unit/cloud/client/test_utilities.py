"""
Unit tests for the cloud.client.utilities module


"""


from cloudadapter.cloud.client.utilities import (
    ProxyConfig, TLSConfig, Formatter, MethodParser
)

import unittest
import mock


class TestProxyConfig(unittest.TestCase):

    @mock.patch('cloudadapter.cloud.client.utilities.getproxies', autospec=True)
    def test_manual_proxy_succeeds(self, mock_getproxies):
        mock_getproxies.return_value = {
            "http": "http://proxy.com:123/"
        }
        endpoint = "other-proxy", 456
        proxy_config = ProxyConfig(*endpoint)
        assert proxy_config.endpoint == endpoint

    @mock.patch('cloudadapter.cloud.client.utilities.getproxies', autospec=True)
    def test_auto_proxy_succeeds(self, mock_getproxies):
        mock_getproxies.return_value = {
            "http": "http://proxy.com:123/"
        }
        proxy_config = ProxyConfig()
        assert proxy_config.endpoint == ("proxy.com", 123)


class TestTLSConfig(unittest.TestCase):

    @mock.patch('cloudadapter.cloud.client.utilities.SSLContext', autospec=True)
    def test_tls_config_succeeds(self, MockSSLContext):
        tls_config = TLSConfig("location")
        assert tls_config.context is MockSSLContext.return_value

    @mock.patch('cloudadapter.cloud.client.utilities.SSLContext', autospec=True)
    def test_tls_config_with_bad_certificates_fails(self, MockSSLContext):
        MockSSLContext.return_value.load_verify_locations.side_effect = IOError("Error!")
        failed = False
        try:
            TLSConfig("location")
        except OSError:
            failed = True
        assert failed


class TestFormatter(unittest.TestCase):

    def test_format_unformatted_succeeds(self):
        formatter = Formatter("unformatted")
        result = formatter.format()
        assert result == "unformatted"

    def test_format_supplies_timestamps_succeeds(self):
        formatter = Formatter("{ts} {timestamp} {timestamp=%c}")
        result = formatter.format()
        assert "{ts}" not in result
        assert "{timestamp" not in result

    def test_format_supplies_defaults_succeeds(self):
        formatter = Formatter("{default}", {"default": "filled"})
        result = formatter.format()
        assert result == "filled"

    def test_format_supplies_given_succeeds(self):
        formatter = Formatter("{given}")
        result = formatter.format(given="filled")
        assert result == "filled"

    def test_format_escapes_succeeds(self):
        formatter = Formatter("{escape}")
        result = formatter.format(escape="\r\t\n\"")
        assert result == "\\r\\t\\n\\\""

    def test_raw_format_no_escapes(self):
        formatter = Formatter("{raw_escape}")
        result = formatter.format(escape="\r\t\n\"")
        assert result == "\r\t\n\""

    def test_raw_format_no_escapes_default(self):
        formatter = Formatter("{raw_default}", {"default": "f\"illed"})
        result = formatter.format()
        assert result == "f\"illed"

    def test_format_backslash_escape_succeeds(self):
        formatter = Formatter("{escape}")
        result = formatter.format(escape="\\")
        assert result == "\\\\"

    @mock.patch('cloudadapter.cloud.client.utilities.logger', autospec=True)
    def test_format_not_supplied_logged_succeeds(self, mock_logger):
        formatter = Formatter("{unsupplied}")
        formatter.format()
        assert mock_logger.error.call_count == 1


class TestMethodParse(unittest.TestCase):

    def setUp(self):
        self.parse_info = {
            "method": {
                "regex": r"methods\/([\w_-]+)",
                "group": 1
            },
            "args": {
                "path": "parent/child/item"
            }
        }
        self.parser = MethodParser(self.parse_info)

    def test_parse_single_succeeds(self):
        topic = "methods/my-method"
        payload = "{ \"parent\": { \"child\": { \"item\": { \"param\": \"arg\" } } } }"
        result = self.parser.parse(topic, payload)[0]
        assert result.method == "my-method"
        assert result.args.get("param") is not None

    def test_parse_single_without_method_succeeds(self):
        topic = "methods"
        payload = "{ \"parent\": { \"child\": { \"item\": { \"param\": \"arg\" } } } }"
        result = self.parser.parse(topic, payload)[0]
        assert not result.method
        assert result.args.get("param") is not None

    def test_parse_single_without_args_succeeds(self):
        topic = "methods/my-method"
        payload = "{ }"
        result = self.parser.parse(topic, payload)[0]

        assert result.method == "my-method"
        assert not result.args

    def test_parse_invalid_payload_fails(self):
        failed = False
        try:
            self.parser.parse("topic", "payload")
        except ValueError:
            failed = True
        assert failed

    def test_parse_multiple_succeeds(self):
        aggregate_info = {
            "path": "methods"
        }
        parser = MethodParser(self.parse_info, aggregate_info)
        topic = "methods/my-method"
        payload = ("{ \"methods\": ["
                   "{ \"parent\": { \"child\": { \"item\": { \"param\": \"arg\" } } } },"
                   "{ \"parent\": { \"child\": { \"item\": { \"param\": \"arg\" } } } },"
                   "{ \"parent\": { \"child\": { \"item\": { \"param\": \"arg\" } } } } ] }")
        results = parser.parse(topic, payload)
        assert len(results) == 3
