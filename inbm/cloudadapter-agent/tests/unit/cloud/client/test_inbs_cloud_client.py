"""
Unit tests for the InbsCloudClient


"""


from cloudadapter.cloud.client.inbs_cloud_client import InbsCloudClient
from cloudadapter.cloud.adapters.proto import inbs_sb_pb2
import unittest
from cloudadapter.cloud.client.inbs_cloud_client import grpc
from unittest.mock import patch, MagicMock
from datetime import datetime

class TestInbsCloudClient(unittest.TestCase):

    @patch("cloudadapter.cloud.client.inbs_cloud_client.grpc.insecure_channel")
    @patch("cloudadapter.cloud.adapters.proto.inbs_sb_pb2_grpc.INBSServiceStub")
    def setUp(self, mock_stub, mock_channel):
        self.grpc_hostname = "localhost"
        self.grpc_port = "50051"
        self.inbs_client = InbsCloudClient(grpc_hostname=self.grpc_hostname, grpc_port=self.grpc_port)
        self.mock_channel = mock_channel
        self.mock_stub = mock_stub

    def test_constructor_initializes_values(self):
        self.assertEqual(self.inbs_client._grpc_hostname, self.grpc_hostname)
        self.assertEqual(self.inbs_client._grpc_port, self.grpc_port)
        self.assertFalse(self.inbs_client._stop_event.is_set())

    def test_get_client_id_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            client_id = self.inbs_client.get_client_id()
    
    def test_publish_telemetry_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.inbs_client.publish_telemetry(key="example_key", value="example_value", time=datetime.now())

    def test_publish_event_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.inbs_client.publish_event(key="example_event", value="event_value")

    def test_publish_attribute_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.inbs_client.publish_attribute(key="example_attribute", value="attribute_value")

    @patch("cloudadapter.cloud.client.inbs_cloud_client.queue.Queue")
    def test_ping_pong_yield_response_on_ping_request(self, mock_queue):
        ping_pong_gen = self.inbs_client._ping_pong(mock_queue)
        mock_request = MagicMock()
        mock_queue.get.return_value = mock_request
        self.inbs_client._stop_event.clear()  # ensuring stop event is not set for the test

        response = next(ping_pong_gen)
        self.assertIsInstance(response, inbs_sb_pb2.PingResponse)
    
    @patch("cloudadapter.cloud.client.inbs_cloud_client.time.sleep", side_effect=InterruptedError)
    @patch("grpc.insecure_channel")
    @patch("cloudadapter.cloud.adapters.proto.inbs_sb_pb2_grpc.INBSServiceStub")
    def test_run_grpc_error(self, mock_stub, mock_channel, mock_sleep):
        # Setup aRpcError to simulate gRPC error
        mock_channel.side_effect = MagicMock(side_effect=grpc.RpcError())

        self.inbs_client._stop_event.clear()
        with self.assertRaises(InterruptedError):  # To stop the infinite loop
            self.inbs_client._run()

        mock_sleep.assert_called()  # Check that backoff sleep was called

    @patch("cloudadapter.cloud.client.inbs_cloud_client.queue.Queue")
    def test_run_stop_event_sets(self, mock_queue):
        self.inbs_client._stop_event.set()  # Act like we want to stop immediately
        self.inbs_client._run()

        # If the method exits immediately, it means the stop event was respected
        mock_queue.assert_not_called()


if __name__ == '__main__':
    unittest.main()