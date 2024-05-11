"""
Unit tests for the InbsCloudClient


"""


from cloudadapter.cloud.client.inbs_cloud_client import InbsCloudClient
from cloudadapter.pb.inbs.v1 import inbs_sb_pb2
import unittest
from cloudadapter.cloud.client.inbs_cloud_client import grpc
from unittest.mock import patch, MagicMock, Mock
from datetime import datetime
import queue


class TestInbsCloudClient(unittest.TestCase):

    @patch("cloudadapter.cloud.client.inbs_cloud_client.grpc.insecure_channel")
    @patch("cloudadapter.pb.inbs.v1.inbs_sb_pb2_grpc.INBSSBServiceStub")
    def setUp(self, mock_stub, mock_channel):
        self.hostname = "localhost"
        self.port = "50051"
        self.node_id = "node_id"
        self.token = "token"
        self.inbs_client = InbsCloudClient(
            hostname=self.hostname,
            port=self.port,
            node_id=self.node_id,
            tls_enabled=False,
            tls_cert=None,
            token=None)
        self.mock_channel = mock_channel
        self.mock_stub = mock_stub

    def test_constructor_initializes_values(self):
        self.assertEqual(self.inbs_client._grpc_hostname, self.hostname)
        self.assertEqual(self.inbs_client._grpc_port, self.port)
        self.assertEqual(self.inbs_client._client_id, self.node_id)
        self.assertEqual(self.inbs_client._metadata, [
                         ("node-id", self.node_id)])

    def test_get_client_id(self):
        client_id = self.inbs_client.get_client_id()
        self.assertEqual(client_id, self.node_id)

    def test_publish_telemetry(self):
        # this is  not expected to do anything yet
        self.inbs_client.publish_telemetry(
            key="example_key", value="example_value", time=datetime.now())

    def test_publish_event(self):
        # this is not expected to do anything yet
        self.inbs_client.publish_event(key="example_event", value="event_value")

    def test_publish_attribute(self):
        # this is not expected to do anything yet
        self.inbs_client.publish_attribute(key="example_attribute", value="attribute_value")

    def test_single_ping_request(self):
        # Mocks
        request_queue = queue.Queue()
        stop_event = Mock()
        stop_event.is_set.return_value = False

        # Set up the INBMRequest with PingRequest
        ping_request = inbs_sb_pb2.INBMRequest(
            request_id="123", ping_request=inbs_sb_pb2.PingRequest())
        request_queue.put(ping_request)
        # Signal end of queue processing (in real code this isn't needed, here to stop the generator)
        request_queue.put(None)

        self.inbs_client._stop_event = stop_event

        # Run test
        generator = self.inbs_client._handle_inbm_command(request_queue)
        response = next(generator)

        # Check the response correctness
        self.assertEqual(response.request_id, "123")
        self.assertTrue(hasattr(response, 'ping_response'))

        # Cleanup, ensure nothing else is left in the generator
        with self.assertRaises(StopIteration):
            next(generator)

    @patch("cloudadapter.cloud.client.inbs_cloud_client.time.sleep", side_effect=InterruptedError)
    @patch("grpc.insecure_channel")
    @patch("cloudadapter.pb.inbs.v1.inbs_sb_pb2_grpc.INBSSBServiceStub")
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
