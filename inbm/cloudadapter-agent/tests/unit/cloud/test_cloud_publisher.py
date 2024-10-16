"""
Unit tests for the CloudPublisher class


"""


import unittest
import mock

import time
import json
import datetime

from cloudadapter.exceptions import PublishError
from cloudadapter.cloud.cloud_publisher import CloudPublisher


class TestCloudPublisher(unittest.TestCase):

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    @mock.patch('cloudadapter.cloud.adapters.adapter.Adapter', autospec=True)
    def setUp(self, MockedAdapter, mock_logger) -> None:
        self.MockedAdapter = MockedAdapter
        self.cloud_publisher = CloudPublisher(self.MockedAdapter("config"))

    def test_publish_node_update_succeed(self) -> None:
        update = "update"
        self.cloud_publisher.publish_node_update(update)

        mocked = self.MockedAdapter.return_value
        mocked.publish_node_update.assert_called_once_with(update)
                    
    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_node_update_with_adapter__succeeds(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_node_update.return_value = None
        self.cloud_publisher.publish_node_update('{"status": 200, "message": "COMMAND SUCCESSFUL", "job_id": "swupd-0cdce9d5-523b-43d9-8673-d54fd61498fe"}')
        assert mock_logger.error.call_count == 0
        
    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_node_update_with_adapter_fails(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_node_update.side_effect = PublishError("Error!")
        self.cloud_publisher.publish_node_update('{"status": 200, "message": "COMMAND SUCCESSFUL", "job_id": "swupd-0cdce9d5-523b-43d9-8673-d54fd61498fe"}')
        assert mock_logger.error.call_count == 1
        
    def test_publish_event_succeed(self) -> None:
        event = "event"
        self.cloud_publisher.publish_event(event)

        mocked = self.MockedAdapter.return_value
        mocked.publish_event.assert_called_once_with(event)
        
    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_event_with_adapter_succeeds(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_event.return_value = None
        self.cloud_publisher.publish_event("Test Event")
        assert mock_logger.error.call_count == 0

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_event_with_adapter_fails(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_event.side_effect = PublishError("Error!")
        self.cloud_publisher.publish_event("Test Event")
        assert mock_logger.error.call_count == 1

    def test_publish_telemetry_static_succeed(self) -> None:
        telemetry = {
            "type": "static_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            }
        }

        self.cloud_publisher.publish_telemetry(json.dumps(telemetry))

        mocked = self.MockedAdapter.return_value
        mocked.publish_attribute.assert_called_once_with("TestAttribute", "Test Value")

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_static_with_adapter_succeeds(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_attribute.return_value = None
        telemetry = json.dumps({
            "type": "static_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            }
        })
        self.cloud_publisher.publish_telemetry(telemetry)
        assert mock_logger.error.call_count == 0

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_static_with_adapter_fails(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_attribute.side_effect = PublishError("Error!")
        telemetry = json.dumps({
            "type": "static_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            }
        })
        self.cloud_publisher.publish_telemetry(telemetry)
        assert mock_logger.error.call_count == 1

    def test_publish_telemetry_dynamic_succeed(self) -> None:
        telemetry = {
            "type": "dynamic_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            },
            "timestamp": time.time()
        }

        self.cloud_publisher.publish_telemetry(json.dumps(telemetry))

        mocked = self.MockedAdapter.return_value
        timestamp = str(telemetry.get("timestamp"))
        mocked.publish_telemetry.assert_called_once_with(
            "TestAttribute",
            "Test Value",
            datetime.datetime.utcfromtimestamp(int(float(timestamp)))
        )

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_dynamic_with_adapter_success_succeeds(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_telemetry.return_value = None
        telemetry = json.dumps({
            "type": "dynamic_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            }
        })
        self.cloud_publisher.publish_telemetry(telemetry)
        assert mock_logger.error.call_count == 0

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_dynamic_with_adapter_fail_fails(self, mock_logger) -> None:
        self.MockedAdapter.return_value.publish_telemetry.side_effect = PublishError("Error!")
        telemetry = json.dumps({
            "type": "dynamic_telemetry",
            "values": {
                "TestAttribute": "Test Value"
            }
        })
        self.cloud_publisher.publish_telemetry(telemetry)
        assert mock_logger.error.call_count == 1

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_unkown_fail(self, mock_logger) -> None:
        telemetry = json.dumps({
            "values": {
                "TestAttribute": "Test Value"
            }
        })

        self.cloud_publisher.publish_telemetry(telemetry)

        assert mock_logger.error.call_count == 1
        mock_logger.error.assert_called_once_with(
            "Telemetry JSON is missing telemetry_type: %s",
            telemetry
        )

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_empty_fail(self, mock_logger) -> None:
        telemetry = json.dumps({})

        self.cloud_publisher.publish_telemetry(telemetry)

        assert mock_logger.error.call_count == 1
        mock_logger.error.assert_called_once_with(
            "Telemetry JSON is missing telemetry_type: %s",
            telemetry
        )

    @mock.patch("cloudadapter.cloud.cloud_publisher.logger")
    def test_publish_telemetry_bad_json_fail(self, mock_logger) -> None:
        telemetry = "invalid"

        self.cloud_publisher.publish_telemetry(telemetry)

        assert mock_logger.error.call_count == 1
        mock_logger.error.assert_called_once_with(
            "Issue parsing telemetry JSON: %s",
            telemetry
        )
