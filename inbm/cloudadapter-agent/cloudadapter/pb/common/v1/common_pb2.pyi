"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
DO NOT EDIT: this file is imported by earthly +generate-proto from this location: https://raw.githubusercontent.com/intel/intel-inb-manageability/0a41be1e5ac99e36814f58cb837dba7ddc9b04af/inbm/proto/common/v1/common.proto"""

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
class Error(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    MESSAGE_FIELD_NUMBER: builtins.int
    message: builtins.str
    def __init__(
        self,
        *,
        message: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["message", b"message"]) -> None: ...

global___Error = Error

@typing.final
class NodeScheduledOperations(google.protobuf.message.Message):
    """one node could have multiple operations (SOTA, FOTA, etc) each with their own schedules"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SCHEDULED_OPERATIONS_FIELD_NUMBER: builtins.int
    NODE_ID_FIELD_NUMBER: builtins.int
    node_id: builtins.str
    @property
    def scheduled_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ScheduledOperation]: ...
    def __init__(
        self,
        *,
        scheduled_operations: collections.abc.Iterable[global___ScheduledOperation] | None = ...,
        node_id: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["node_id", b"node_id", "scheduled_operations", b"scheduled_operations"]) -> None: ...

global___NodeScheduledOperations = NodeScheduledOperations

@typing.final
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
    def HasField(self, field_name: typing.Literal["operation", b"operation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["operation", b"operation", "schedules", b"schedules"]) -> None: ...

global___ScheduledOperation = ScheduledOperation

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
    """this is different from MM's SingleSchedule in that it is using google's Timestamp"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    JOB_ID_FIELD_NUMBER: builtins.int
    START_TIME_FIELD_NUMBER: builtins.int
    END_TIME_FIELD_NUMBER: builtins.int
    job_id: builtins.str
    """This will be created by MJunct.  This will be empty coming into MJunct NB API.  Else, it should have a string value."""
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
    def HasField(self, field_name: typing.Literal["end_time", b"end_time", "start_time", b"start_time"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["end_time", b"end_time", "job_id", b"job_id", "start_time", b"start_time"]) -> None: ...

global___SingleSchedule = SingleSchedule

@typing.final
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
    """This will be created by MJunct.  This will be empty coming into MJunct NB API.  Else, it should have a string value."""
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
        job_id: builtins.str = ...,
        duration: google.protobuf.duration_pb2.Duration | None = ...,
        cron_minutes: builtins.str = ...,
        cron_hours: builtins.str = ...,
        cron_day_month: builtins.str = ...,
        cron_month: builtins.str = ...,
        cron_day_week: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["duration", b"duration"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["cron_day_month", b"cron_day_month", "cron_day_week", b"cron_day_week", "cron_hours", b"cron_hours", "cron_minutes", b"cron_minutes", "cron_month", b"cron_month", "duration", b"duration", "job_id", b"job_id"]) -> None: ...

global___RepeatedSchedule = RepeatedSchedule

@typing.final
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
    UPDATE_FIRMWARE_OPERATION_FIELD_NUMBER: builtins.int
    service_type: global___Operation.ServiceType.ValueType
    @property
    def pre_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PreOperation]: ...
    @property
    def post_operations(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___PostOperation]: ...
    @property
    def update_system_software_operation(self) -> global___UpdateSystemSoftwareOperation: ...
    @property
    def set_power_state_operation(self) -> global___SetPowerStateOperation: ...
    @property
    def update_firmware_operation(self) -> global___UpdateFirmwareOperation:
        """and others"""

    def __init__(
        self,
        *,
        pre_operations: collections.abc.Iterable[global___PreOperation] | None = ...,
        post_operations: collections.abc.Iterable[global___PostOperation] | None = ...,
        service_type: global___Operation.ServiceType.ValueType = ...,
        update_system_software_operation: global___UpdateSystemSoftwareOperation | None = ...,
        set_power_state_operation: global___SetPowerStateOperation | None = ...,
        update_firmware_operation: global___UpdateFirmwareOperation | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["operation", b"operation", "set_power_state_operation", b"set_power_state_operation", "update_firmware_operation", b"update_firmware_operation", "update_system_software_operation", b"update_system_software_operation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["operation", b"operation", "post_operations", b"post_operations", "pre_operations", b"pre_operations", "service_type", b"service_type", "set_power_state_operation", b"set_power_state_operation", "update_firmware_operation", b"update_firmware_operation", "update_system_software_operation", b"update_system_software_operation"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["operation", b"operation"]) -> typing.Literal["update_system_software_operation", "set_power_state_operation", "update_firmware_operation"] | None: ...

global___Operation = Operation

@typing.final
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
    mode: global___UpdateSystemSoftwareOperation.DownloadMode.ValueType
    """Mode for installing the softare update regarding download and install steps."""
    do_not_reboot: builtins.bool
    """Whether to reboot the node after the firmware update attempt"""
    @property
    def release_date(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """Release date of the new SW update."""

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
    def HasField(self, field_name: typing.Literal["release_date", b"release_date"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["do_not_reboot", b"do_not_reboot", "mode", b"mode", "package_list", b"package_list", "release_date", b"release_date", "url", b"url"]) -> None: ...

global___UpdateSystemSoftwareOperation = UpdateSystemSoftwareOperation

@typing.final
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
    def ClearField(self, field_name: typing.Literal["opcode", b"opcode"]) -> None: ...

global___SetPowerStateOperation = SetPowerStateOperation

@typing.final
class UpdateFirmwareOperation(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    URL_FIELD_NUMBER: builtins.int
    BIOS_VERSION_FIELD_NUMBER: builtins.int
    VENDOR_FIELD_NUMBER: builtins.int
    MANUFACTURER_FIELD_NUMBER: builtins.int
    PRODUCT_NAME_FIELD_NUMBER: builtins.int
    RELEASE_DATE_FIELD_NUMBER: builtins.int
    DO_NOT_REBOOT_FIELD_NUMBER: builtins.int
    url: builtins.str
    """URL from which to remotely retrieve the package"""
    bios_version: builtins.str
    """BIOS version of the new firmware update."""
    vendor: builtins.str
    """Vendor of the new firmware update."""
    manufacturer: builtins.str
    """Manufacturer of the new firmware update."""
    product_name: builtins.str
    """Product name of the new firmware update."""
    do_not_reboot: builtins.bool
    """Whether to reboot the node after the firmware update attempt"""
    @property
    def release_date(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """Release date of the new SW update."""

    def __init__(
        self,
        *,
        url: builtins.str = ...,
        bios_version: builtins.str = ...,
        vendor: builtins.str = ...,
        manufacturer: builtins.str = ...,
        product_name: builtins.str = ...,
        release_date: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        do_not_reboot: builtins.bool = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["release_date", b"release_date"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["bios_version", b"bios_version", "do_not_reboot", b"do_not_reboot", "manufacturer", b"manufacturer", "product_name", b"product_name", "release_date", b"release_date", "url", b"url", "vendor", b"vendor"]) -> None: ...

global___UpdateFirmwareOperation = UpdateFirmwareOperation

@typing.final
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

@typing.final
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

@typing.final
class Job(google.protobuf.message.Message):
    """this message represents a Job and can be used in multiple contexts; see RPC definitions
    for some definitions fields may be ignored; e.g., when reporting job status up from a node,
    the node_id is ignored and is filled in by INBS
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    class _ExecutedBy:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _ExecutedByEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Job._ExecutedBy.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        EXECUTED_BY_UNSPECIFIED: Job._ExecutedBy.ValueType  # 0
        EXECUTED_BY_INBAND: Job._ExecutedBy.ValueType  # 1
        EXECUTED_BY_OOB: Job._ExecutedBy.ValueType  # 2

    class ExecutedBy(_ExecutedBy, metaclass=_ExecutedByEnumTypeWrapper): ...
    EXECUTED_BY_UNSPECIFIED: Job.ExecutedBy.ValueType  # 0
    EXECUTED_BY_INBAND: Job.ExecutedBy.ValueType  # 1
    EXECUTED_BY_OOB: Job.ExecutedBy.ValueType  # 2

    class _JobState:
        ValueType = typing.NewType("ValueType", builtins.int)
        V: typing_extensions.TypeAlias = ValueType

    class _JobStateEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Job._JobState.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        JOB_STATE_UNSPECIFIED: Job._JobState.ValueType  # 0
        SCHEDULED: Job._JobState.ValueType  # 1
        STARTED: Job._JobState.ValueType  # 2
        PASSED: Job._JobState.ValueType  # 3
        FAILED: Job._JobState.ValueType  # 4

    class JobState(_JobState, metaclass=_JobStateEnumTypeWrapper): ...
    JOB_STATE_UNSPECIFIED: Job.JobState.ValueType  # 0
    SCHEDULED: Job.JobState.ValueType  # 1
    STARTED: Job.JobState.ValueType  # 2
    PASSED: Job.JobState.ValueType  # 3
    FAILED: Job.JobState.ValueType  # 4

    JOB_ID_FIELD_NUMBER: builtins.int
    NODE_ID_FIELD_NUMBER: builtins.int
    SCHEDULE_ID_FIELD_NUMBER: builtins.int
    EXECUTED_BY_FIELD_NUMBER: builtins.int
    DESIRED_START_TIME_FIELD_NUMBER: builtins.int
    ACTUAL_START_TIME_FIELD_NUMBER: builtins.int
    ACTUAL_END_TIME_FIELD_NUMBER: builtins.int
    JOB_STATE_FIELD_NUMBER: builtins.int
    STATUS_CODE_FIELD_NUMBER: builtins.int
    RESULT_MSGS_FIELD_NUMBER: builtins.int
    CREATE_TIME_FIELD_NUMBER: builtins.int
    job_id: builtins.str
    """UUID with abbreviated type"""
    node_id: builtins.str
    """UUID, references NODE(node_id)"""
    schedule_id: builtins.int
    """References SCHEDULE(schedule_id)"""
    executed_by: global___Job.ExecutedBy.ValueType
    job_state: global___Job.JobState.ValueType
    status_code: builtins.int
    """Not yet defined"""
    result_msgs: builtins.str
    """JSON string for result messages of all tasks ran"""
    @property
    def desired_start_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    @property
    def actual_start_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    @property
    def actual_end_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    @property
    def create_time(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    def __init__(
        self,
        *,
        job_id: builtins.str = ...,
        node_id: builtins.str = ...,
        schedule_id: builtins.int = ...,
        executed_by: global___Job.ExecutedBy.ValueType = ...,
        desired_start_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        actual_start_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        actual_end_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        job_state: global___Job.JobState.ValueType = ...,
        status_code: builtins.int = ...,
        result_msgs: builtins.str = ...,
        create_time: google.protobuf.timestamp_pb2.Timestamp | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["actual_end_time", b"actual_end_time", "actual_start_time", b"actual_start_time", "create_time", b"create_time", "desired_start_time", b"desired_start_time"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["actual_end_time", b"actual_end_time", "actual_start_time", b"actual_start_time", "create_time", b"create_time", "desired_start_time", b"desired_start_time", "executed_by", b"executed_by", "job_id", b"job_id", "job_state", b"job_state", "node_id", b"node_id", "result_msgs", b"result_msgs", "schedule_id", b"schedule_id", "status_code", b"status_code"]) -> None: ...

global___Job = Job
