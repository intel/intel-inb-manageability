# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import inbs_sb_pb2 as proto_dot_inbs__sb__pb2


class INBSSBServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.INBMCommand = channel.stream_stream(
                '/inbs.v1.INBSSBService/INBMCommand',
                request_serializer=proto_dot_inbs__sb__pb2.INBMResponse.SerializeToString,
                response_deserializer=proto_dot_inbs__sb__pb2.INBMRequest.FromString,
                )


class INBSSBServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def INBMCommand(self, request_iterator, context):
        """Bi-directional streaming method
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_INBSSBServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'INBMCommand': grpc.stream_stream_rpc_method_handler(
                    servicer.INBMCommand,
                    request_deserializer=proto_dot_inbs__sb__pb2.INBMResponse.FromString,
                    response_serializer=proto_dot_inbs__sb__pb2.INBMRequest.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'inbs.v1.INBSSBService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class INBSSBService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def INBMCommand(request_iterator,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.stream_stream(request_iterator, target, '/inbs.v1.INBSSBService/INBMCommand',
            proto_dot_inbs__sb__pb2.INBMResponse.SerializeToString,
            proto_dot_inbs__sb__pb2.INBMRequest.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
