"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""

import builtins
import google.protobuf.descriptor
import google.protobuf.message
import typing

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing.final
class INBMRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    PING_REQUEST_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def ping_request(self) -> global___PingRequest: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        ping_request: global___PingRequest | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["payload", b"payload", "ping_request", b"ping_request"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["payload", b"payload", "ping_request", b"ping_request", "request_id", b"request_id"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["payload", b"payload"]) -> typing.Literal["ping_request"] | None: ...

global___INBMRequest = INBMRequest

@typing.final
class INBMResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    PING_RESPONSE_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def ping_response(self) -> global___PingResponse: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        ping_response: global___PingResponse | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["payload", b"payload", "ping_response", b"ping_response"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["payload", b"payload", "ping_response", b"ping_response", "request_id", b"request_id"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["payload", b"payload"]) -> typing.Literal["ping_response"] | None: ...

global___INBMResponse = INBMResponse

@typing.final
class PingRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PingRequest = PingRequest

@typing.final
class PingResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PingResponse = PingResponse
