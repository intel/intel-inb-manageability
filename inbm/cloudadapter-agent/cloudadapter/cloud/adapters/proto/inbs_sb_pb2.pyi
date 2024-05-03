"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""

import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import typing

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing.final
class INBMRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    REQUEST_DATA_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def request_data(self) -> global___INBMRequestPayload: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        request_data: global___INBMRequestPayload | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["request_data", b"request_data"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["request_data", b"request_data", "request_id", b"request_id"]) -> None: ...

global___INBMRequest = INBMRequest

@typing.final
class INBMResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    REQUEST_ID_FIELD_NUMBER: builtins.int
    RESPONSE_DATA_FIELD_NUMBER: builtins.int
    request_id: builtins.str
    @property
    def response_data(self) -> global___INBMResponsePayload: ...
    def __init__(
        self,
        *,
        request_id: builtins.str = ...,
        response_data: global___INBMResponsePayload | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["response_data", b"response_data"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["request_id", b"request_id", "response_data", b"response_data"]) -> None: ...

global___INBMResponse = INBMResponse

@typing.final
class INBMRequestPayload(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PING_REQUEST_FIELD_NUMBER: builtins.int
    SET_SOTA_SCHEDULE_REQUEST_FIELD_NUMBER: builtins.int
    @property
    def ping_request(self) -> global___PingRequestPayload: ...
    @property
    def set_sota_schedule_request(self) -> global___SetSOTAScheduleRequestPayload: ...
    def __init__(
        self,
        *,
        ping_request: global___PingRequestPayload | None = ...,
        set_sota_schedule_request: global___SetSOTAScheduleRequestPayload | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["payload", b"payload", "ping_request", b"ping_request", "set_sota_schedule_request", b"set_sota_schedule_request"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["payload", b"payload", "ping_request", b"ping_request", "set_sota_schedule_request", b"set_sota_schedule_request"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["payload", b"payload"]) -> typing.Literal["ping_request", "set_sota_schedule_request"] | None: ...

global___INBMRequestPayload = INBMRequestPayload

@typing.final
class INBMResponsePayload(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PING_RESPONSE_FIELD_NUMBER: builtins.int
    SET_SOTA_SCHEDULE_RESPONSE_FIELD_NUMBER: builtins.int
    @property
    def ping_response(self) -> global___PingResponsePayload: ...
    @property
    def set_sota_schedule_response(self) -> global___SetSOTAScheduleResponsePayload: ...
    def __init__(
        self,
        *,
        ping_response: global___PingResponsePayload | None = ...,
        set_sota_schedule_response: global___SetSOTAScheduleResponsePayload | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["payload", b"payload", "ping_response", b"ping_response", "set_sota_schedule_response", b"set_sota_schedule_response"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["payload", b"payload", "ping_response", b"ping_response", "set_sota_schedule_response", b"set_sota_schedule_response"]) -> None: ...
    def WhichOneof(self, oneof_group: typing.Literal["payload", b"payload"]) -> typing.Literal["ping_response", "set_sota_schedule_response"] | None: ...

global___INBMResponsePayload = INBMResponsePayload

@typing.final
class PingRequestPayload(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PingRequestPayload = PingRequestPayload

@typing.final
class PingResponsePayload(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___PingResponsePayload = PingResponsePayload

@typing.final
class SetSOTAScheduleRequestPayload(google.protobuf.message.Message):
    """TODO: re-add the validate.rules from maintenance manager to the repeated_schedules fields. prerequisite: get the validate.proto import working"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing.final
    class UpdateSource(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        KERNEL_COMMAND_FIELD_NUMBER: builtins.int
        OS_REPO_URL_FIELD_NUMBER: builtins.int
        CUSTOM_REPOS_FIELD_NUMBER: builtins.int
        kernel_command: builtins.str
        """Kernel command line"""
        os_repo_url: builtins.str
        """'DEB822 Source Format' url to the public repository"""
        @property
        def custom_repos(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]:
            """'DEB822 Source Format' entries for Debian style OSs"""

        def __init__(
            self,
            *,
            kernel_command: builtins.str = ...,
            os_repo_url: builtins.str = ...,
            custom_repos: collections.abc.Iterable[builtins.str] | None = ...,
        ) -> None: ...
        def ClearField(self, field_name: typing.Literal["custom_repos", b"custom_repos", "kernel_command", b"kernel_command", "os_repo_url", b"os_repo_url"]) -> None: ...

    @typing.final
    class UpdateSchedule(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        @typing.final
        class SingleSchedule(google.protobuf.message.Message):
            DESCRIPTOR: google.protobuf.descriptor.Descriptor

            START_SECONDS_FIELD_NUMBER: builtins.int
            END_SECONDS_FIELD_NUMBER: builtins.int
            start_seconds: builtins.int
            """start of one-time schedule (required)"""
            end_seconds: builtins.int
            """end of one-time schedule (optional)"""
            def __init__(
                self,
                *,
                start_seconds: builtins.int = ...,
                end_seconds: builtins.int = ...,
            ) -> None: ...
            def ClearField(self, field_name: typing.Literal["end_seconds", b"end_seconds", "start_seconds", b"start_seconds"]) -> None: ...

        @typing.final
        class RepeatedSchedule(google.protobuf.message.Message):
            DESCRIPTOR: google.protobuf.descriptor.Descriptor

            DURATION_SECONDS_FIELD_NUMBER: builtins.int
            CRON_MINUTES_FIELD_NUMBER: builtins.int
            CRON_HOURS_FIELD_NUMBER: builtins.int
            CRON_DAY_MONTH_FIELD_NUMBER: builtins.int
            CRON_MONTH_FIELD_NUMBER: builtins.int
            CRON_DAY_WEEK_FIELD_NUMBER: builtins.int
            duration_seconds: builtins.int
            """between 1 second and 86400 seconds (24 hours worth of seconds)"""
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
                duration_seconds: builtins.int = ...,
                cron_minutes: builtins.str = ...,
                cron_hours: builtins.str = ...,
                cron_day_month: builtins.str = ...,
                cron_month: builtins.str = ...,
                cron_day_week: builtins.str = ...,
            ) -> None: ...
            def ClearField(self, field_name: typing.Literal["cron_day_month", b"cron_day_month", "cron_day_week", b"cron_day_week", "cron_hours", b"cron_hours", "cron_minutes", b"cron_minutes", "cron_month", b"cron_month", "duration_seconds", b"duration_seconds"]) -> None: ...

        SINGLE_SCHEDULE_FIELD_NUMBER: builtins.int
        REPEATED_SCHEDULES_FIELD_NUMBER: builtins.int
        @property
        def single_schedule(self) -> global___SetSOTAScheduleRequestPayload.UpdateSchedule.SingleSchedule: ...
        @property
        def repeated_schedules(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___SetSOTAScheduleRequestPayload.UpdateSchedule.RepeatedSchedule]: ...
        def __init__(
            self,
            *,
            single_schedule: global___SetSOTAScheduleRequestPayload.UpdateSchedule.SingleSchedule | None = ...,
            repeated_schedules: collections.abc.Iterable[global___SetSOTAScheduleRequestPayload.UpdateSchedule.RepeatedSchedule] | None = ...,
        ) -> None: ...
        def HasField(self, field_name: typing.Literal["single_schedule", b"single_schedule"]) -> builtins.bool: ...
        def ClearField(self, field_name: typing.Literal["repeated_schedules", b"repeated_schedules", "single_schedule", b"single_schedule"]) -> None: ...

    UPDATE_SOURCE_FIELD_NUMBER: builtins.int
    UPDATE_SCHEDULE_FIELD_NUMBER: builtins.int
    INSTALLED_PACKAGES_FIELD_NUMBER: builtins.int
    installed_packages: builtins.str
    """Freeform text, OS-dependent. A list of package names, one per line (newline separated). Should not contain version info."""
    @property
    def update_source(self) -> global___SetSOTAScheduleRequestPayload.UpdateSource: ...
    @property
    def update_schedule(self) -> global___SetSOTAScheduleRequestPayload.UpdateSchedule: ...
    def __init__(
        self,
        *,
        update_source: global___SetSOTAScheduleRequestPayload.UpdateSource | None = ...,
        update_schedule: global___SetSOTAScheduleRequestPayload.UpdateSchedule | None = ...,
        installed_packages: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["update_schedule", b"update_schedule", "update_source", b"update_source"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["installed_packages", b"installed_packages", "update_schedule", b"update_schedule", "update_source", b"update_source"]) -> None: ...

global___SetSOTAScheduleRequestPayload = SetSOTAScheduleRequestPayload

@typing.final
class SetSOTAScheduleResponsePayload(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___SetSOTAScheduleResponsePayload = SetSOTAScheduleResponsePayload
