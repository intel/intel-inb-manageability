"""
Unit tests for the cloudadapter file


"""


import unittest
import mock
import sys

import cloudadapter.cloudadapter as cloudadapter
from cloudadapter.cloudadapter import CloudAdapter
from cloudadapter.exceptions import BadConfigError


class TestCloudAdapter(unittest.TestCase):

    @mock.patch('cloudadapter.cloudadapter.fileConfig', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Waiter', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Client', autospec=True)
    def test_cloudadapter_starts_client_succeeds(self, MockClient, MockWaiter, mock_fileConfig) -> None:
        cloudadapter.main()
        assert MockClient.return_value.start.call_count == 1

    @mock.patch('cloudadapter.cloudadapter.fileConfig', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.logging', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Waiter', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Client', autospec=True)
    def test_cloudadapter_logs_and_exits_client_error_succeeds(
            self, MockClient, MockWaiter, mock_logging, mock_fileConfig) -> None:
        MockClient.side_effect = BadConfigError("Error!")
        mock_logger = mock_logging.getLogger.return_value
        cloudadapter.main()
        if sys.version_info >= (3, 6):
            assert mock_logger.error.call_count == 1
        else:
            assert mock_logger.error.call_count == 2
        assert MockClient.return_value.start.call_count == 0

    @mock.patch('cloudadapter.cloudadapter.fileConfig', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Waiter', autospec=True)
    @mock.patch('cloudadapter.cloudadapter.Client', autospec=True)
    def test_service_name_prefixed_inbm(self, MockClient, MockWaiter, mock_fileConfig) -> None:
        ca = CloudAdapter()
        self.assertFalse(' ' in ca._svc_name_)
        self.assertEqual(ca._svc_name_.split('-')[0], 'inbm')
