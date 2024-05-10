"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""

import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.duration_pb2
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import google.protobuf.timestamp_pb2
import sys
import typing

if sys.version_info >= (3, 10):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing.final
class HandleINBMCommandRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    PING_REQUEST_FIELD_NUMBER: builtins.int
    UPDATE_SCHEDULED_TASKS_REQUEST_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def ping_request(self) -> global___PingRequest: ...
    @property
    def update_scheduled_tasks_request(self) -> global___UpdateScheduledTasksRequest: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        ping_request: global___PingRequest | None = ...,
        update_scheduled_tasks_request: global___UpdateScheduledTasksRequest | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["ping_request", b"ping_request", "request", b"request", "update_scheduled_tasks_request", b"update_scheduled_tasks_request"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["ping_request", b"ping_request", "request", b"request", "request_id", b"request_id", "update_scheduled_tasks_request", b"update_scheduled_tasks_request"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["request", b"request"]) -> typing.Literal["ping_request", "update_scheduled_tasks_request"] | None: ...

global___HandleINBMCommandRequest = HandleINBMCommandRequest

@typing.final
class HandleINBMCommandResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    PING_RESPONSE_FIELD_NUMBER: builtins.int
    UPDATE_SCHEDULED_TASKS_RESPONSE_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def ping_response(self) -> global___PingResponse: ...
    @property
    def update_scheduled_tasks_response(self) -> global___UpdateScheduledTasksResponse: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        ping_response: global___PingResponse | None = ...,
        update_scheduled_tasks_response: global___UpdateScheduledTasksResponse | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["ping_response", b"ping_response", "response", b"response", "update_scheduled_tasks_response", b"update_scheduled_tasks_response"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["ping_response", b"ping_response", "request_id", b"request_id", "response", b"response", "update_scheduled_tasks_response", b"update_scheduled_tasks_response"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["response", b"response"]) -> typing.Literal["ping_response", "update_scheduled_tasks_response"] | None: ...

global___HandleINBMCommandResponse = HandleINBMCommandResponse

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

@typing.final
class UpdateScheduledTasksRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    TASKS_FIELD_NUMBER: builtins.int
    @property
    def tasks(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ScheduledTask]: ...
    def __init__(
        self,
        *,
        tasks: collections.abc.Iterable[global___ScheduledTask] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["tasks", b"tasks"]) -> None: ...

global___UpdateScheduledTasksRequest = UpdateScheduledTasksRequest

@typing.final
class UpdateScheduledTasksResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___UpdateScheduledTasksResponse = UpdateScheduledTasksResponse

@typing.final
class ScheduledTask(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    OPERATION_FIELD_NUMBER: builtins.int
    SCHEDULES_FIELD_NUMBER: builtins.int
    @property
    def operation(self) -> global___Operation: ...
    @property
    def schedules(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Schedule]: ...
    def __init__(
        self,
        *,
        operation: global___Operation | None = ...,
        schedules: collections.abc.Iterable[global___Schedule] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["operation", b"operation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["operation", b"operation", "schedules", b"schedules"]) -> None: ...

global___ScheduledTask = ScheduledTask

@typing.final
class Operation(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PRE_OPERATIONS_FIELD_NUMBER: builtins.int
    POST_OPERATIONS_FIELD_NUMBER: builtins.int
    UPDATE_SYSTEM_SOFTWARE_REQUEST_FIELD_NUMBER: builtins.int
    UPDATE_FIRMWARE_REQUEST_FIELD_NUMBER: builtins.int
    @property
    def pre_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PreOperation]: ...
    @property
    def post_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PostOperation]: ...
    @property
    def update_system_software_request(self) -> global___UpdateSystemSoftwareRequest: ...
    @property
    def update_firmware_request(self) -> global___UpdateFirmwareRequest:
        """..."""

    def __init__(
        self,
        *,
        pre_operations: collections.abc.Iterable[global___PreOperation] | None = ...,
        post_operations: collections.abc.Iterable[global___PostOperation] | None = ...,
        update_system_software_request: global___UpdateSystemSoftwareRequest | None = ...,
        update_firmware_request: global___UpdateFirmwareRequest | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["operation_type", b"operation_type", "update_firmware_request", b"update_firmware_request", "update_system_software_request", b"update_system_software_request"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["operation_type", b"operation_type", "post_operations", b"post_operations", "pre_operations", b"pre_operations", "update_firmware_request", b"update_firmware_request", "update_system_software_request", b"update_system_software_request"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["operation_type", b"operation_type"]) -> typing.Literal["update_system_software_request", "update_firmware_request"] | None: ...

global___Operation = Operation

@typing.final
class PreOperation(google.protobuf.message.Message):
    """ oneof type {
     // ...
     }
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PreOperation = PreOperation

@typing.final
class PostOperation(google.protobuf.message.Message):
    """ oneof type {
     // ...
    }
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PostOperation = PostOperation

@typing.final
class UpdateSystemSoftwareRequest(google.protobuf.message.Message):
    """Performs a software update on the desired nodes"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    URL_FIELD_NUMBER: builtins.int
    RELEASE_DATE_FIELD_NUMBER: builtins.int
    MODE_FIELD_NUMBER: builtins.int
    DO_NOT_REBOOT_FIELD_NUMBER: builtins.int
    PACKAGE_LIST_FIELD_NUMBER: builtins.int
    do_not_reboot: builtins.bool
    """Whether to reboot the node after the firmware update attempt"""
    @property
    def url(self) -> global___Url:
        """URL from which to remotely retrieve the package"""

    @property
    def release_date(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """Release date of the new SW update."""

    @property
    def mode(self) -> global___DownloadMode:
        """Mode for installing the softare update regarding download and install steps."""

    @property
    def package_list(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]:
        """List of packages to install if whole package update isn't desired."""

    def __init__(
        self,
        *,
        url: global___Url | None = ...,
        release_date: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        mode: global___DownloadMode | None = ...,
        do_not_reboot: builtins.bool = ...,
        package_list: collections.abc.Iterable[builtins.str] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["mode", b"mode", "release_date", b"release_date", "url", b"url"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["do_not_reboot", b"do_not_reboot", "mode", b"mode", "package_list", b"package_list", "release_date", b"release_date", "url", b"url"]) -> None: ...

global___UpdateSystemSoftwareRequest = UpdateSystemSoftwareRequest

@typing.final
class UpdateFirmwareRequest(google.protobuf.message.Message):
    """Performs a firmware update after retrieving the update package
    from a remote source.
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    URL_FIELD_NUMBER: builtins.int
    RELEASE_DATE_FIELD_NUMBER: builtins.int
    VENDOR_FIELD_NUMBER: builtins.int
    MANUFACTURER_FIELD_NUMBER: builtins.int
    PRODUCT_FIELD_NUMBER: builtins.int
    MODEL_FIELD_NUMBER: builtins.int
    SIGNATURE_FIELD_NUMBER: builtins.int
    TOOL_OPTIONS_FIELD_NUMBER: builtins.int
    DO_NOT_REBOOT_FIELD_NUMBER: builtins.int
    vendor: builtins.str
    """Firmware vendor"""
    manufacturer: builtins.str
    """Hardware manufacturer"""
    product: builtins.str
    """System board product type"""
    model: builtins.str
    """System board model number"""
    signature: builtins.str
    """Software signature to validate the update package"""
    tool_options: builtins.str
    """Flags that the firmware update tool may use"""
    do_not_reboot: builtins.bool
    """Weather to reboot the node after the firmware update attempt"""
    @property
    def url(self) -> global___Url:
        """URL from which to remotely retrieve the package"""

    @property
    def release_date(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """Release date of the new FW update"""

    def __init__(
        self,
        *,
        url: global___Url | None = ...,
        release_date: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        vendor: builtins.str = ...,
        manufacturer: builtins.str = ...,
        product: builtins.str = ...,
        model: builtins.str = ...,
        signature: builtins.str | None = ...,
        tool_options: builtins.str | None = ...,
        do_not_reboot: builtins.bool | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["_do_not_reboot", b"_do_not_reboot", "_signature", b"_signature", "_tool_options", b"_tool_options", "do_not_reboot", b"do_not_reboot", "release_date", b"release_date", "signature", b"signature", "tool_options", b"tool_options", "url", b"url"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["_do_not_reboot", b"_do_not_reboot", "_signature", b"_signature", "_tool_options", b"_tool_options", "do_not_reboot", b"do_not_reboot", "manufacturer", b"manufacturer", "model", b"model", "product", b"product", "release_date", b"release_date", "signature", b"signature", "tool_options", b"tool_options", "url", b"url", "vendor", b"vendor"]) -> None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing.Literal["_do_not_reboot", b"_do_not_reboot"]) -> typing.Literal["do_not_reboot"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing.Literal["_signature", b"_signature"]) -> typing.Literal["signature"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing.Literal["_tool_options", b"_tool_options"]) -> typing.Literal["tool_options"] | None: ...

global___UpdateFirmwareRequest = UpdateFirmwareRequest

@typing.final
class Url(google.protobuf.message.Message):
    """Defines the URL structure"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _Scheme:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _SchemeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Url._Scheme.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        SCHEME_UNSPECIFIED: Url._Scheme.ValueType  # 0
        """Default value.  This will produce an error"""
        SCHEME_HTTPS: Url._Scheme.ValueType  # 1
        """HyperText Transfer Protocol Secure"""
        SCHEME_FTP: Url._Scheme.ValueType  # 2
        """File transfer protocol"""
        SCHEME_FILE: Url._Scheme.ValueType  # 3
        """Host-Specific File Names"""

    class Scheme(_Scheme, metaclass=_SchemeEnumTypeWrapper): ...
    SCHEME_UNSPECIFIED: Url.Scheme.ValueType  # 0
    """Default value.  This will produce an error"""
    SCHEME_HTTPS: Url.Scheme.ValueType  # 1
    """HyperText Transfer Protocol Secure"""
    SCHEME_FTP: Url.Scheme.ValueType  # 2
    """File transfer protocol"""
    SCHEME_FILE: Url.Scheme.ValueType  # 3
    """Host-Specific File Names"""

    SCHEME_FIELD_NUMBER: builtins.int
    ADDRESS_FIELD_NUMBER: builtins.int
    USERNAME_FIELD_NUMBER: builtins.int
    scheme: global___Url.Scheme.ValueType
    """URL Scheme such as https://"""
    address: builtins.str
    """Contains domain, path, port, query, and fragment of the address"""
    username: builtins.str
    """Username if required to retrieve the file"""
    def __init__(
        self,
        *,
        scheme: global___Url.Scheme.ValueType = ...,
        address: builtins.str = ...,
        username: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["address", b"address", "scheme", b"scheme", "username", b"username"]) -> None: ...

global___Url = Url

@typing.final
class DownloadMode(google.protobuf.message.Message):
    """Specifies the mode for installing the Software update.  This allows for the steps of downloading
    and installing to be seperated into two different actions.
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _Mode:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _ModeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[DownloadMode._Mode.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        MODE_UNSPECIFIED: DownloadMode._Mode.ValueType  # 0
        MODE_FULL: DownloadMode._Mode.ValueType  # 1
        """Both download the package and install the package"""
        MODE_NO_DOWNLOAD: DownloadMode._Mode.ValueType  # 2
        """Do not download the package.  Only install."""
        MODE_DOWNLOAD_ONLY: DownloadMode._Mode.ValueType  # 3
        """Only download the package.  Do not install."""

    class Mode(_Mode, metaclass=_ModeEnumTypeWrapper): ...
    MODE_UNSPECIFIED: DownloadMode.Mode.ValueType  # 0
    MODE_FULL: DownloadMode.Mode.ValueType  # 1
    """Both download the package and install the package"""
    MODE_NO_DOWNLOAD: DownloadMode.Mode.ValueType  # 2
    """Do not download the package.  Only install."""
    MODE_DOWNLOAD_ONLY: DownloadMode.Mode.ValueType  # 3
    """Only download the package.  Do not install."""

    MODE_FIELD_NUMBER: builtins.int
    mode: global___DownloadMode.Mode.ValueType
    """Mode for installing the Software update."""
    def __init__(
        self,
        *,
        mode: global___DownloadMode.Mode.ValueType = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["mode", b"mode"]) -> None: ...

global___DownloadMode = DownloadMode

@typing.final
class Schedule(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SINGLE_SCHEDULE_FIELD_NUMBER: builtins.int
    REPEATED_SCHEDULE_FIELD_NUMBER: builtins.int
    @property
    def single_schedule(self) -> global___SingleSchedule: ...
    @property
    def repeated_schedule(self) -> global___RepeatedSchedule: ...
    def __init__(
        self,
        *,
        single_schedule: global___SingleSchedule | None = ...,
        repeated_schedule: global___RepeatedSchedule | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["repeated_schedule", b"repeated_schedule", "schedule", b"schedule", "single_schedule", b"single_schedule"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["repeated_schedule", b"repeated_schedule", "schedule", b"schedule", "single_schedule", b"single_schedule"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["schedule", b"schedule"]) -> typing.Literal["single_schedule", "repeated_schedule"] | None: ...

global___Schedule = Schedule

@typing.final
class SingleSchedule(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    START_TIME_FIELD_NUMBER: builtins.int
    END_TIME_FIELD_NUMBER: builtins.int
    @property
    def start_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    @property
    def end_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    def __init__(
        self,
        *,
        start_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        end_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["end_time", b"end_time", "start_time", b"start_time"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["end_time", b"end_time", "start_time", b"start_time"]) -> None: ...

global___SingleSchedule = SingleSchedule

@typing.final
class RepeatedSchedule(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    DURATION_FIELD_NUMBER: builtins.int
    CRON_MINUTES_FIELD_NUMBER: builtins.int
    CRON_HOURS_FIELD_NUMBER: builtins.int
    CRON_DAY_MONTH_FIELD_NUMBER: builtins.int
    CRON_MONTH_FIELD_NUMBER: builtins.int
    CRON_DAY_WEEK_FIELD_NUMBER: builtins.int
    cron_minutes: builtins.str
    """cron style minutes (0-59)"""
    cron_hours: builtins.str
    """cron style hours (0-23)"""
    cron_day_month: builtins.str
    """cron style day of month (0-31)"""
    cron_month: builtins.str
    """cron style month (1-12)"""
    cron_day_week: builtins.str
    """cron style day of week (0-6)"""
    @property
    def duration(self) -> google.protobuf.duration_pb2.Duration:
        """should be between 1 second and 86400 seconds (24 hours worth of seconds)"""

    def __init__(
        self,
        *,
        duration: google.protobuf.duration_pb2.Duration | None = ...,
        cron_minutes: builtins.str = ...,
        cron_hours: builtins.str = ...,
        cron_day_month: builtins.str = ...,
        cron_month: builtins.str = ...,
        cron_day_week: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["duration", b"duration"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["cron_day_month", b"cron_day_month", "cron_day_week", b"cron_day_week", "cron_hours", b"cron_hours", "cron_minutes", b"cron_minutes", "cron_month", b"cron_month", "duration", b"duration"]) -> None: ...

global___RepeatedSchedule = RepeatedSchedule
