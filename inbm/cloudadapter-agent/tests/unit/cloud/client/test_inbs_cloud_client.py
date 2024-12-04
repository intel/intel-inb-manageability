import uuid
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
        
    def test_publish_attribute_bios_release_date(self, inbs_client: InbsCloudClient) -> None:
        key = "biosReleaseDate"
        value = "2021-01-01T00:00:00"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            bios_release_date=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.bios_release_date == expected_request.static_telemetry.bios_release_date
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_bios_version(self, inbs_client: InbsCloudClient) -> None:
        key = "biosVersion"
        value = "BNKBL357.86A.0080.2019.0725.1139"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            bios_version=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.bios_version == expected_request.static_telemetry.bios_version
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_bios_vendor(self, inbs_client: InbsCloudClient) -> None:
        key = "biosVendor"
        value = "Intel Corporation"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            bios_vendor=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.bios_vendor == expected_request.static_telemetry.bios_vendor
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_system_product_name(self, inbs_client: InbsCloudClient) -> None:
        key = "systemProductName"
        value = "ABC"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            system_product_name=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.system_product_name == expected_request.static_telemetry.system_product_name
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_total_physical_memory(self, inbs_client: InbsCloudClient) -> None:
        key = "totalPhysicalMemory"
        value = "8203132928"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            total_physical_memory_bytes=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.total_physical_memory_bytes == expected_request.static_telemetry.total_physical_memory_bytes
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_system_manufacturer(self, inbs_client: InbsCloudClient) -> None:
        key = "systemManufacturer"
        value = "Intel Corporation"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            system_manufacturer=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.system_manufacturer == expected_request.static_telemetry.system_manufacturer
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_power_capabilities(self, inbs_client: InbsCloudClient) -> None:
        key = "powerCapabilities"
        value = '{"shutdown": true, "reboot": true, "suspend": true, "hibernate": true}'
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            power_capabilities=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.power_capabilities == expected_request.static_telemetry.power_capabilities
            
        assert kwargs['metadata'] == inbs_client._metadata
    
    def test_publish_attribute_os_info(self, inbs_client: InbsCloudClient) -> None:
        key = "osInformation"
        value = 'Linux nat2-desktop 6.8.0-49-generic #49~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Nov  6 17:42:15 UTC 2 x86_64 x86_64'
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            os_information=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.os_information == expected_request.static_telemetry.os_information
            
        assert kwargs['metadata'] == inbs_client._metadata
        
    def test_publish_attribute_cpu_id(self, inbs_client: InbsCloudClient) -> None:
        key = "cpuId"
        value = "Intel(R) Core(TM) i7-7567U CPU @ 3.50GHz"
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            cpu_id=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.cpu_id == expected_request.static_telemetry.cpu_id
            
        assert kwargs['metadata'] == inbs_client._metadata
    
    def test_publish_attribute_os_info(self, inbs_client: InbsCloudClient) -> None:
        key = "diskInformation"
        value = '[{\"NAME\": \"loop0\", \"SIZE\": \"4096\", \"SSD\": \"True\"}, {\"NAME\": \"loop1\", \"SIZE\": \"58363904\", \"SSD\": \"True\"}, {\"NAME\": \"loop2\", \"SIZE\": \"58052608\", \"SSD\": \"True\"}, {\"NAME\": \"loop3\", \"SIZE\": \"67080192\", \"SSD\": \"True\"}, {\"NAME\": \"loop4\", \"SIZE\": \"66789376\", \"SSD\": \"True\"}, {\"NAME\": \"loop5\", \"SIZE\": \"77463552\", \"SSD\": \"True\"}, {\"NAME\": \"loop6\", \"SIZE\": \"76771328\", \"SSD\": \"True\"}, {\"NAME\": \"loop7\", \"SIZE\": \"46448640\", \"SSD\": \"True\"}, {\"NAME\": \"loop8\", \"SIZE\": \"286236672\", \"SSD\": \"True\"}, {\"NAME\": \"loop9\", \"SIZE\": \"366678016\", \"SSD\": \"True\"}, {\"NAME\": \"loop10\", \"SIZE\": \"366682112\", \"SSD\": \"True\"}, {\"NAME\": \"loop11\", \"SIZE\": \"528642048\", \"SSD\": \"True\"}, {\"NAME\": \"loop12\", \"SIZE\": \"529625088\", \"SSD\": \"True\"}, {\"NAME\": \"loop13\", \"SIZE\": \"96141312\", \"SSD\": \"True\"}, {\"NAME\": \"loop14\", \"SIZE\": \"181411840\", \"SSD\": \"True\"}, {\"NAME\": \"loop15\", \"SIZE\": \"181428224\", \"SSD\": \"True\"}, {\"NAME\": \"loop16\", \"SIZE\": \"790515712\", \"SSD\": \"True\"}, {\"NAME\": \"loop17\", \"SIZE\": \"787800064\", \"SSD\": \"True\"}, {\"NAME\": \"loop18\", \"SIZE\": \"13553664\", \"SSD\": \"True\"}, {\"NAME\": \"loop19\", \"SIZE\": \"12791808\", \"SSD\": \"True\"}, {\"NAME\": \"loop21\", \"SIZE\": \"40714240\", \"SSD\": \"True\"}, {\"NAME\": \"loop22\", \"SIZE\": \"577536\", \"SSD\": \"True\"}, {\"NAME\": \"loop23\", \"SIZE\": \"581632\", \"SSD\": \"True\"}, {\"NAME\": \"loop24\", \"SIZE\": \"25190400\", \"SSD\": \"True\"}, {\"NAME\": \"loop25\", \"SIZE\": \"25354240\", \"SSD\": \"True\"}, {\"NAME\": \"loop26\", \"SIZE\": \"33554432\", \"SSD\": \"True\"}, {\"NAME\": \"loop27\", \"SIZE\": \"287358976\", \"SSD\": \"True\"}, {\"NAME\": \"sda\", \"SIZE\": \"512110190592\", \"SSD\": \"True\"}]'
        
        inbs_client._grpc_channel = MagicMock()
        inbs_client.publish_attribute(key, value)

        expected_static_telemetry = common_pb2.StaticTelemetry(
            node_id=inbs_client._client_id,
            disk_information=value
        )
        expected_request = inbs_sb_pb2.SendNodeUpdateRequest(
            request_id=str(uuid.uuid4()),
            job_update=None,
            static_telemetry=expected_static_telemetry
        )

        inbs_client._grpc_channel.SendNodeUpdate.assert_called_once()
        args, kwargs = inbs_client._grpc_channel.SendNodeUpdate.call_args
        actual_request = args[0]

        assert actual_request.static_telemetry.node_id == expected_request.static_telemetry.node_id        
        assert actual_request.static_telemetry.disk_information == expected_request.static_telemetry.disk_information
            
        assert kwargs['metadata'] == inbs_client._metadata

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
