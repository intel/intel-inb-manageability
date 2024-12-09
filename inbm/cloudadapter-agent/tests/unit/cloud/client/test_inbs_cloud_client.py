import pytest
from mock import MagicMock, Mock, patch
import queue
from cloudadapter.exceptions import PublishError
import grpc # type: ignore
from datetime import datetime
from typing import Generator

from cloudadapter.constants import RUNNING, DEAD
from cloudadapter.pb.inbs.v1 import inbs_sb_pb2
from cloudadapter.pb.common.v1 import common_pb2
from cloudadapter.cloud.client.inbs_cloud_client import InbsCloudClient


@pytest.fixture
def inbs_client() -> Generator[InbsCloudClient, None, None]:
    hostname = "localhost"
    port = "50051"
    node_id = "node_id"
    tls_enabled = False
    tls_cert = None
    token = None

    with patch(
        "cloudadapter.cloud.client.inbs_cloud_client.grpc.insecure_channel"
    ), patch("cloudadapter.pb.inbs.v1.inbs_sb_pb2_grpc.INBSSBServiceStub"):
        yield InbsCloudClient(
            hostname=hostname,
            port=port,
            node_id=node_id,
            tls_enabled=tls_enabled,
            tls_cert=tls_cert,
            token=token,
        )


class TestInbsCloudClient:
    def test_constructor_initializes_values(self, inbs_client: InbsCloudClient) -> None:
        assert inbs_client._grpc_hostname == "localhost"
        assert inbs_client._grpc_port == "50051"
        assert inbs_client._client_id == "node_id"
        assert inbs_client._metadata == [("node-id", "node_id")]

    def test_get_client_id(self, inbs_client: InbsCloudClient) -> None:
        client_id = inbs_client.get_client_id()
        assert client_id == "node_id"

    def test_publish_telemetry(self, inbs_client: InbsCloudClient) -> None:
        # this is not expected to do anything yet
        inbs_client.publish_telemetry(
            key="example_key", value="example_value", time=datetime.now()
        )
    
    def test_publish_node_update(self, inbs_client: InbsCloudClient) -> None:
        mock_channel = MagicMock()
        mock_channel.SendNodeUpdateRequest.return_value = "MockResponse"
        inbs_client._grpc_channel = mock_channel
        
        key = 'update'
        value = '{"status":200, "message":"COMMAND SUCCESSFUL", "job_id":"swupd-4b151b70-c121-4245-873b-5324ac7a3f7a"}'
        
        # Call the publish_update method
        with patch('cloudadapter.cloud.client.inbs_cloud_client.is_valid_json_structure', return_value=True):
            inbs_client.publish_node_update(key, value)

        # Assert that the gRPC channel's SendNodeUpdate method was called
        mock_channel.SendNodeUpdate.assert_called_once()
       

    def test_publish_update_failure_no_grpc_channel(self, inbs_client: InbsCloudClient):
        # Ensure that _grpc_channel is None to simulate the channel not being set up
        inbs_client._grpc_channel = None

        # Define the key and value to be published
        key = 'test-key'
        value = '{"job_id": "12345", "status": 200, "message": "Update successful"}'

        # Call the publish_node_update method and expect a PublishError
        with pytest.raises(PublishError):
            inbs_client.publish_node_update(key, value)
    
    def test_publish_event(self, inbs_client: InbsCloudClient) -> None:
        # this is not expected to do anything yet
        inbs_client.publish_event(key="example_event", value="event_value")

    def test_publish_attribute(self, inbs_client: InbsCloudClient) -> None:
        # this is not expected to do anything yet
        inbs_client.publish_attribute(key="example_attribute", value="attribute_value")

    @pytest.mark.parametrize(
        "request_id, dispatcher_error_response, command_type, expected_response, expected_xml",
        [
            (
                "123",
                "",
                inbs_sb_pb2.INBMCommand(ping=inbs_sb_pb2.Ping()),
                inbs_sb_pb2.HandleINBMCommandResponse(request_id="123"),
                ""
            ),
            (
                "124",
                "",
                inbs_sb_pb2.INBMCommand(
                    update_scheduled_operations=inbs_sb_pb2.UpdateScheduledOperations()
                ),
                inbs_sb_pb2.HandleINBMCommandResponse(
                    request_id="124",
                ),
                "<schedule_request><request_id>124</request_id></schedule_request>"
            ),
            (
                "124",
                "test message",
                inbs_sb_pb2.INBMCommand(
                    update_scheduled_operations=inbs_sb_pb2.UpdateScheduledOperations()
                ),
                inbs_sb_pb2.HandleINBMCommandResponse(
                    request_id="124",
                    error=common_pb2.Error(message="test message"),
                ),
                "<schedule_request><request_id>124</request_id></schedule_request>"
            ),
        ],
    )
    def test_single_command(
        self,
        inbs_client: InbsCloudClient,
        request_id: str,
        dispatcher_error_response: str,
        command_type: inbs_sb_pb2.INBMCommand,
        expected_response: inbs_sb_pb2.HandleINBMCommandResponse,
        expected_xml: str,
    ) -> None:
        # Setup
        request_queue: queue.Queue[
            inbs_sb_pb2.HandleINBMCommandRequest | None
        ] = queue.Queue()
        stop_event = Mock()
        stop_event.is_set.return_value = False

        # Set dispatcher state
        inbs_client.set_dispatcher_state(RUNNING)

        # set up the triggerota callback to see what is sent to dispatcher
        triggered_str = ""

        def triggerschedule(xml: str, id: str, timeout: int) -> str:
            nonlocal triggered_str
            triggered_str = xml
            return dispatcher_error_response

        inbs_client.bind_callback('triggerschedule', triggerschedule)

        # Construct command using parameters
        command = inbs_sb_pb2.HandleINBMCommandRequest(
            request_id=request_id, command=command_type
        )
        request_queue.put(command)
        request_queue.put(None)  # Sentinel to end the generator

        inbs_client._stop_event = stop_event

        # Execute
        generator = inbs_client._handle_inbm_command_request(request_queue)
        response = next(generator)

        # Validate
        assert response == expected_response
        assert triggered_str == expected_xml

        # Cleanup
        with pytest.raises(StopIteration):
            next(generator)
    
    def test_handle_command_when_dispatcher_is_not_up(self, inbs_client: InbsCloudClient) -> None:
        # Setup
        request_queue: queue.Queue[
            inbs_sb_pb2.HandleINBMCommandRequest | None
        ] = queue.Queue()
        stop_event = Mock()
        stop_event.is_set.return_value = False

        # Set dispatcher state
        inbs_client.set_dispatcher_state(DEAD)

        # Construct command using parameters
        command = inbs_sb_pb2.HandleINBMCommandRequest(
            request_id="123", command=inbs_sb_pb2.INBMCommand(update_scheduled_operations=inbs_sb_pb2.UpdateScheduledOperations())
        )
        request_queue.put(command)
        request_queue.put(None)  # Sentinel to end the generator
        generator = inbs_client._handle_inbm_command_request(request_queue)
        response = next(generator)

        # Validate
        assert response == inbs_sb_pb2.HandleINBMCommandResponse(
                    request_id="123",
                    error=common_pb2.Error(message="INBM Cloudadapter: Unable to process request. Please try again"),
                )

    def test_run_stop_event_sets(self, inbs_client: InbsCloudClient) -> None:
        with patch(
            "cloudadapter.cloud.client.inbs_cloud_client.queue.Queue"
        ) as mock_queue, patch.object(inbs_client, '_grpc_channel', new_callable=MagicMock):
            inbs_client._stop_event.set()  # Act like we want to stop immediately
            inbs_client._run()

            # If the method exits immediately, it means the stop event was respected
            mock_queue.assert_not_called()
