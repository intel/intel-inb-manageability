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

@typing_extensions.final
class Error(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    MESSAGE_FIELD_NUMBER: builtins.int
    message: builtins.str
    def __init__(
        self,
        *,
        message: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["message", b"message"]) -> None: ...

global___Error = Error

@typing_extensions.final
class NodeScheduledOperations(google.protobuf.message.Message):
    """one node could have multiple operations (SOTA, FOTA, etc) each with their own schedules"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SCHEDULED_OPERATIONS_FIELD_NUMBER: builtins.int
    NODE_ID_FIELD_NUMBER: builtins.int
    @property
    def scheduled_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ScheduledOperation]: ...
    node_id: builtins.str
    def __init__(
        self,
        *,
        scheduled_operations: collections.abc.Iterable[global___ScheduledOperation] | None = ...,
        node_id: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["node_id", b"node_id", "scheduled_operations", b"scheduled_operations"]) -> None: ...

global___NodeScheduledOperations = NodeScheduledOperations

@typing_extensions.final
class ScheduledOperation(google.protobuf.message.Message):
    """this is one operation with a set of times to run"""

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
    def HasField(self, field_name: typing_extensions.Literal["operation", b"operation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["operation", b"operation", "schedules", b"schedules"]) -> None: ...

global___ScheduledOperation = ScheduledOperation

@typing_extensions.final
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
    def HasField(self, field_name: typing_extensions.Literal["repeated_schedule", b"repeated_schedule", "schedule", b"schedule", "single_schedule", b"single_schedule"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["repeated_schedule", b"repeated_schedule", "schedule", b"schedule", "single_schedule", b"single_schedule"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["schedule", b"schedule"]) -> typing_extensions.Literal["single_schedule", "repeated_schedule"] | None: ...

global___Schedule = Schedule

@typing_extensions.final
class SingleSchedule(google.protobuf.message.Message):
    """this is different from MM's SingleSchedule in that it is using google's Timestamp"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    JOB_ID_FIELD_NUMBER: builtins.int
    START_TIME_FIELD_NUMBER: builtins.int
    END_TIME_FIELD_NUMBER: builtins.int
    job_id: builtins.str
    @property
    def start_time(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """to specify running immeidate, omit start time and end time"""
    @property
    def end_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    def __init__(
        self,
        *,
        job_id: builtins.str = ...,
        start_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        end_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["end_time", b"end_time", "job_id", b"job_id", "start_time", b"start_time"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["end_time", b"end_time", "job_id", b"job_id", "start_time", b"start_time"]) -> None: ...

global___SingleSchedule = SingleSchedule

@typing_extensions.final
class RepeatedSchedule(google.protobuf.message.Message):
    """this is different from MM's SingleSchedule in that it is using google's Duration"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    JOB_ID_FIELD_NUMBER: builtins.int
    DURATION_FIELD_NUMBER: builtins.int
    CRON_MINUTES_FIELD_NUMBER: builtins.int
    CRON_HOURS_FIELD_NUMBER: builtins.int
    CRON_DAY_MONTH_FIELD_NUMBER: builtins.int
    CRON_MONTH_FIELD_NUMBER: builtins.int
    CRON_DAY_WEEK_FIELD_NUMBER: builtins.int
    job_id: builtins.str
    @property
    def duration(self) -> google.protobuf.duration_pb2.Duration:
        """should be between 1 second and 86400 seconds (24 hours worth of seconds)"""
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
    def __init__(
        self,
        *,
        job_id: builtins.str = ...,
        duration: google.protobuf.duration_pb2.Duration | None = ...,
        cron_minutes: builtins.str = ...,
        cron_hours: builtins.str = ...,
        cron_day_month: builtins.str = ...,
        cron_month: builtins.str = ...,
        cron_day_week: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["duration", b"duration", "job_id", b"job_id"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["cron_day_month", b"cron_day_month", "cron_day_week", b"cron_day_week", "cron_hours", b"cron_hours", "cron_minutes", b"cron_minutes", "cron_month", b"cron_month", "duration", b"duration", "job_id", b"job_id"]) -> None: ...

global___RepeatedSchedule = RepeatedSchedule

@typing_extensions.final
class Operation(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _ServiceType:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _ServiceTypeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Operation._ServiceType.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        SERVICE_TYPE_UNSPECIFIED: Operation._ServiceType.ValueType  # 0
        SERVICE_TYPE_INBS: Operation._ServiceType.ValueType  # 1
        SERVICE_TYPE_OOB_AMT: Operation._ServiceType.ValueType  # 2
        SERVICE_TYPE_OOB_BMC: Operation._ServiceType.ValueType  # 3
        SERVICE_TYPE_AUTO: Operation._ServiceType.ValueType  # 4

    class ServiceType(_ServiceType, metaclass=_ServiceTypeEnumTypeWrapper): ...
    SERVICE_TYPE_UNSPECIFIED: Operation.ServiceType.ValueType  # 0
    SERVICE_TYPE_INBS: Operation.ServiceType.ValueType  # 1
    SERVICE_TYPE_OOB_AMT: Operation.ServiceType.ValueType  # 2
    SERVICE_TYPE_OOB_BMC: Operation.ServiceType.ValueType  # 3
    SERVICE_TYPE_AUTO: Operation.ServiceType.ValueType  # 4

    PRE_OPERATIONS_FIELD_NUMBER: builtins.int
    POST_OPERATIONS_FIELD_NUMBER: builtins.int
    SERVICE_TYPE_FIELD_NUMBER: builtins.int
    UPDATE_SYSTEM_SOFTWARE_OPERATION_FIELD_NUMBER: builtins.int
    SET_POWER_STATE_OPERATION_FIELD_NUMBER: builtins.int
    @property
    def pre_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PreOperation]: ...
    @property
    def post_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PostOperation]: ...
    service_type: global___Operation.ServiceType.ValueType
    @property
    def update_system_software_operation(self) -> global___UpdateSystemSoftwareOperation: ...
    @property
    def set_power_state_operation(self) -> global___SetPowerStateOperation:
        """and others"""
    def __init__(
        self,
        *,
        pre_operations: collections.abc.Iterable[global___PreOperation] | None = ...,
        post_operations: collections.abc.Iterable[global___PostOperation] | None = ...,
        service_type: global___Operation.ServiceType.ValueType = ...,
        update_system_software_operation: global___UpdateSystemSoftwareOperation | None = ...,
        set_power_state_operation: global___SetPowerStateOperation | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["operation", b"operation", "set_power_state_operation", b"set_power_state_operation", "update_system_software_operation", b"update_system_software_operation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["operation", b"operation", "post_operations", b"post_operations", "pre_operations", b"pre_operations", "service_type", b"service_type", "set_power_state_operation", b"set_power_state_operation", "update_system_software_operation", b"update_system_software_operation"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["operation", b"operation"]) -> typing_extensions.Literal["update_system_software_operation", "set_power_state_operation"] | None: ...

global___Operation = Operation

@typing_extensions.final
class UpdateSystemSoftwareOperation(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _DownloadMode:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _DownloadModeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[UpdateSystemSoftwareOperation._DownloadMode.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        DOWNLOAD_MODE_UNSPECIFIED: UpdateSystemSoftwareOperation._DownloadMode.ValueType  # 0
        DOWNLOAD_MODE_FULL: UpdateSystemSoftwareOperation._DownloadMode.ValueType  # 1
        """Both download the package and install the package"""
        DOWNLOAD_MODE_NO_DOWNLOAD: UpdateSystemSoftwareOperation._DownloadMode.ValueType  # 2
        """Do not download the package.  Only install."""
        DOWNLOAD_MODE_DOWNLOAD_ONLY: UpdateSystemSoftwareOperation._DownloadMode.ValueType  # 3
        """Only download the package.  Do not install."""

    class DownloadMode(_DownloadMode, metaclass=_DownloadModeEnumTypeWrapper): ...
    DOWNLOAD_MODE_UNSPECIFIED: UpdateSystemSoftwareOperation.DownloadMode.ValueType  # 0
    DOWNLOAD_MODE_FULL: UpdateSystemSoftwareOperation.DownloadMode.ValueType  # 1
    """Both download the package and install the package"""
    DOWNLOAD_MODE_NO_DOWNLOAD: UpdateSystemSoftwareOperation.DownloadMode.ValueType  # 2
    """Do not download the package.  Only install."""
    DOWNLOAD_MODE_DOWNLOAD_ONLY: UpdateSystemSoftwareOperation.DownloadMode.ValueType  # 3
    """Only download the package.  Do not install."""

    URL_FIELD_NUMBER: builtins.int
    RELEASE_DATE_FIELD_NUMBER: builtins.int
    MODE_FIELD_NUMBER: builtins.int
    DO_NOT_REBOOT_FIELD_NUMBER: builtins.int
    PACKAGE_LIST_FIELD_NUMBER: builtins.int
    url: builtins.str
    """URL from which to remotely retrieve the package"""
    @property
    def release_date(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """Release date of the new SW update."""
    mode: global___UpdateSystemSoftwareOperation.DownloadMode.ValueType
    """Mode for installing the softare update regarding download and install steps."""
    do_not_reboot: builtins.bool
    """Whether to reboot the node after the firmware update attempt"""
    @property
    def package_list(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]:
        """List of packages to install if whole package update isn't desired."""
    def __init__(
        self,
        *,
        url: builtins.str = ...,
        release_date: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        mode: global___UpdateSystemSoftwareOperation.DownloadMode.ValueType = ...,
        do_not_reboot: builtins.bool = ...,
        package_list: collections.abc.Iterable[builtins.str] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["release_date", b"release_date"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["do_not_reboot", b"do_not_reboot", "mode", b"mode", "package_list", b"package_list", "release_date", b"release_date", "url", b"url"]) -> None: ...

global___UpdateSystemSoftwareOperation = UpdateSystemSoftwareOperation

@typing_extensions.final
class SetPowerStateOperation(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _PowerState:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _PowerStateEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[SetPowerStateOperation._PowerState.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        POWER_STATE_UNSPECIFIED: SetPowerStateOperation._PowerState.ValueType  # 0
        POWER_STATE_ON: SetPowerStateOperation._PowerState.ValueType  # 2
        POWER_STATE_CYCLE: SetPowerStateOperation._PowerState.ValueType  # 5
        POWER_STATE_OFF: SetPowerStateOperation._PowerState.ValueType  # 8
        POWER_STATE_RESET: SetPowerStateOperation._PowerState.ValueType  # 10

    class PowerState(_PowerState, metaclass=_PowerStateEnumTypeWrapper): ...
    POWER_STATE_UNSPECIFIED: SetPowerStateOperation.PowerState.ValueType  # 0
    POWER_STATE_ON: SetPowerStateOperation.PowerState.ValueType  # 2
    POWER_STATE_CYCLE: SetPowerStateOperation.PowerState.ValueType  # 5
    POWER_STATE_OFF: SetPowerStateOperation.PowerState.ValueType  # 8
    POWER_STATE_RESET: SetPowerStateOperation.PowerState.ValueType  # 10

    OPCODE_FIELD_NUMBER: builtins.int
    opcode: global___SetPowerStateOperation.PowerState.ValueType
    def __init__(
        self,
        *,
        opcode: global___SetPowerStateOperation.PowerState.ValueType = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["opcode", b"opcode"]) -> None: ...

global___SetPowerStateOperation = SetPowerStateOperation

@typing_extensions.final
class PreOperation(google.protobuf.message.Message):
    """ oneof pre_operation {
       // ...
     }
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PreOperation = PreOperation

@typing_extensions.final
class PostOperation(google.protobuf.message.Message):
    """ oneof post_operation {
       // ...
     }
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PostOperation = PostOperation
