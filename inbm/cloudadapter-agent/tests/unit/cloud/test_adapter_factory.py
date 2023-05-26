"""
Unit tests for the adapter_factory


"""


import unittest
import mock

from cloudadapter.exceptions import BadConfigError
from cloudadapter.cloud.adapter_factory import load_adapter_config, ADAPTER_CONFIG_PATH
import cloudadapter.cloud.adapter_factory as adapter_factory

class TestAdapterFactory(unittest.TestCase):

    def setUp(self):
        self.CONFIG = {
            "sample": "config"
        }

    @mock.patch("os.path.islink")
    def test_islink_error(self, mock_islink):
        # Mock the islink function to return True
        mock_islink.return_value = True

        # Call the load_adapter_config function and assert it raises a BadConfigError
        with self.assertRaises(BadConfigError) as context:
            load_adapter_config()

        # Check if the error message contains the expected text
        self.assertIn(
            f"Configuration file ({ADAPTER_CONFIG_PATH}) is a symbolic link, which is not allowed.",
            str(context.exception),
        )

    @mock.patch('cloudadapter.cloud.adapter_factory.AzureAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_azure_succeeds(self, mock_load_adapter_config, MockAzureAdapter):
        mock_load_adapter_config.return_value = {
            "cloud": "azure",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockAzureAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.TelitAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_telit_succeeds(self, mock_load_adapter_config, MockTelitAdapter):
        mock_load_adapter_config.return_value = {
            "cloud": "telit",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockTelitAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.GenericAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_generic_succeeds(self, mock_load_adapter_config, MockGenericAdapter):
        mock_load_adapter_config.return_value = {
            "cloud": "generic",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockGenericAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.open')
    def test_get_adapter_no_file_fails(self, mock_open):
        mock_open.side_effect = IOError("Error!")
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)

    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_no_cloud_fails(self, mock_load_adapter_config):
        mock_load_adapter_config.return_value = {
            "config": self.CONFIG
        }
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)

    @mock.patch('cloudadapter.cloud.adapter_factory.GenericAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_no_config_fails(self, mock_load_adapter_config, MockGenericAdapter):
        mock_load_adapter_config.return_value = {
            "cloud": "generic",
        }
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)
