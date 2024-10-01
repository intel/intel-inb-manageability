"""
Unit tests for the adapter_factory


"""


import json
import unittest
import mock

from cloudadapter.exceptions import BadConfigError
from cloudadapter.cloud.adapter_factory import load_adapter_config, ADAPTER_CONFIG_PATH
import cloudadapter.cloud.adapter_factory as adapter_factory


class TestAdapterFactory(unittest.TestCase):

    def setUp(self) -> None:
        self.CONFIG = {
            "sample": "config"
        }

    @mock.patch("os.path.islink")
    def test_islink_error(self, mock_islink) -> None:
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

    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config')
    def test_get_adapter_config_filepaths_with_auxiliary_files(self, mock_load):
        mock_load.return_value = {
            "auxiliary_files": ["aux_file_1.json", "aux_file_2.json"]
        }
        filepaths = adapter_factory.get_adapter_config_filepaths()
        self.assertIn("aux_file_1.json", filepaths)
        self.assertIn("aux_file_2.json", filepaths)
        self.assertIn(ADAPTER_CONFIG_PATH, filepaths)    
    
    @mock.patch("os.path.islink", return_value=False)
    @mock.patch("builtins.open")
    def test_load_adapter_config_success(self, mock_open, mock_islink) -> None:
        mock_data = json.dumps({'key': 'value'})
        mock_open.return_value.__enter__.return_value.read.return_value = mock_data
        result = load_adapter_config()
        self.assertEqual(result, {'key': 'value'})       

    @mock.patch('cloudadapter.cloud.adapter_factory.AzureAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_azure_succeeds(self, mock_load_adapter_config, MockAzureAdapter) -> None:
        mock_load_adapter_config.return_value = {
            "cloud": "azure",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockAzureAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.InbsAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_inbs_succeeds(self, mock_load_adapter_config, MockInbsAdapter) -> None:
        mock_load_adapter_config.return_value = {
            "cloud": "inbs",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockInbsAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.GenericAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_generic_succeeds(self, mock_load_adapter_config, MockGenericAdapter) -> None:
        mock_load_adapter_config.return_value = {
            "cloud": "generic",
            "config": self.CONFIG
        }
        adapter_factory.get_adapter()
        assert MockGenericAdapter.call_count == 1

    @mock.patch('cloudadapter.cloud.adapter_factory.open')
    def test_get_adapter_no_file_fails(self, mock_open) -> None:
        mock_open.side_effect = IOError("Error!")
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)

    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_no_cloud_fails(self, mock_load_adapter_config) -> None:
        mock_load_adapter_config.return_value = {
            "config": self.CONFIG
        }
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)

    @mock.patch('cloudadapter.cloud.adapter_factory.GenericAdapter')
    @mock.patch('cloudadapter.cloud.adapter_factory.load_adapter_config', autospec=True)
    def test_get_adapter_no_config_fails(self, mock_load_adapter_config, MockGenericAdapter) -> None:
        mock_load_adapter_config.return_value = {
            "cloud": "generic",
        }
        self.assertRaises(BadConfigError, adapter_factory.get_adapter)
