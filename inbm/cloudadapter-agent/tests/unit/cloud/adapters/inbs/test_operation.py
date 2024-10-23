"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Any
import pytest
from cloudadapter.pb.common.v1.common_pb2 import (
    UpdateSystemSoftwareOperation,
    UpdateFirmwareOperation,
    RpcActivateOperation,
    Operation,
    PreOperation,
    PostOperation,
    ScheduledOperation,
    Schedule,
    SingleSchedule,
    RepeatedSchedule,
)
from cloudadapter.pb.inbs.v1.inbs_sb_pb2 import UpdateScheduledOperations
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.duration_pb2 import Duration
from datetime import datetime
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

# Import the function to be tested
from cloudadapter.cloud.adapters.inbs.operation import (
    convert_system_software_operation_to_xml_manifest,
    convert_firmware_operation_to_xml_manifest,
    convert_rpc_activate_operation_to_xml_manifest,
    convert_operation_to_xml_manifests,
    convert_updated_scheduled_operations_to_dispatcher_xml,
)

RPC_OPERATION_LARGE = RpcActivateOperation(
    url="http://example.com/server",
    profile_name="UDM",
)

RPC_OPERATION_LARGE_MANIFEST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest><type>cmd</type><cmd><header><type>rpc</type></header>"
    '<type><rpc><fetch>http://example.com/server</fetch><profileName>UDM</profileName>'    
    "</rpc></type></cmd></manifest>"
)


SOTA_OPERATION_LARGE = UpdateSystemSoftwareOperation(
    url="http://example.com/update",
    release_date=Timestamp(seconds=int(datetime(2023, 1, 1).timestamp())),
    mode=UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_FULL,
    do_not_reboot=False,
    package_list=["package1", "package2"],
)
SOTA_OPERATION_LARGE_MANIFEST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header>"
    '<type><sota><cmd logtofile="y">update</cmd><mode>full</mode>'
    "<packageList>package1,package2</packageList>"
    "<fetch>http://example.com/update</fetch>"
    "<releaseDate>2023-01-01</releaseDate>"
    "<deviceReboot>yes</deviceReboot>"
    "</sota></type></ota></manifest>"
)
SOTA_OPERATION_SMALL = UpdateSystemSoftwareOperation(
    mode=UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_FULL,
    do_not_reboot=False,
)
SOTA_OPERATION_SMALL_MANIFEST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header>"
    "<type><sota>"
    '<cmd logtofile="y">update</cmd>'
    "<mode>full</mode>"
    "<deviceReboot>yes</deviceReboot>"
    "</sota></type>"
    "</ota></manifest>"
)
FOTA_OPERATION_SMALL = UpdateFirmwareOperation(
    url="http://example.com/update",
    bios_version="1.0.0",
    manufacturer="Intel",
    product_name="Intel NUC",
    vendor="Intel",    
    release_date=Timestamp(seconds=int(datetime(2023, 1, 1).timestamp())),    
    do_not_reboot=False,
)
FOTA_OPERATION_SMALL_MANIFEST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest><type>ota</type><ota><header><type>fota</type><repo>remote</repo></header>"
    "<type><fota name=\"\">"
    "<fetch>http://example.com/update</fetch>"
    "<biosversion>1.0.0</biosversion>"
    "<manufacturer>Intel</manufacturer>"
    "<product>Intel NUC</product>"
    "<vendor>Intel</vendor>"    
    "<releasedate>2023-01-01</releasedate>"
    "<deviceReboot>yes</deviceReboot>"
    "</fota></type>"
    "</ota></manifest>"
)
FOTA_OPERATION_LARGE = UpdateFirmwareOperation(
    url="http://example.com/update",
    bios_version="1.0.0",
    signature_version=384,
    signature="signature",
    manufacturer="Intel",
    product_name="Intel NUC",
    vendor="Intel",    
    release_date=Timestamp(seconds=int(datetime(2023, 1, 1).timestamp())),
    guid="101ae945-7b9f-4765-ad7e-987e2381ad3b",    
    tooloptions="/b /n",
    username="user",
    password="password",
    do_not_reboot=False,
)
FOTA_OPERATION_LARGE_MANIFEST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest><type>ota</type><ota><header><type>fota</type><repo>remote</repo></header>"
    "<type><fota name=\"\">"
    "<fetch>http://example.com/update</fetch>"
    "<biosversion>1.0.0</biosversion>"
    "<signatureversion>384</signatureversion>"
    "<signature>signature</signature>"
    "<manufacturer>Intel</manufacturer>"
    "<product>Intel NUC</product>"
    "<vendor>Intel</vendor>"    
    "<releasedate>2023-01-01</releasedate>"
    "<guid>101ae945-7b9f-4765-ad7e-987e2381ad3b</guid>"
    "<tooloptions>/b /n</tooloptions>"
    "<username>user</username>"
    "<password>password</password>"
    "<deviceReboot>yes</deviceReboot>"
    "</fota></type>"
    "</ota></manifest>"
)


# Test cases to convert UpdateScheduledOperations -> dispatcher XML (success)
@pytest.mark.parametrize(
    "uso, request_id, expected_xml",
    [
        (
            UpdateScheduledOperations(),
            "1234",
            "<schedule_request><request_id>1234</request_id></schedule_request>",
        ),
        (
            UpdateScheduledOperations(
                scheduled_operations=[
                    ScheduledOperation(
                        operation=Operation(
                            post_operations=[],
                            pre_operations=[],
                            update_system_software_operation=SOTA_OPERATION_SMALL,
                        ),
                        schedules=[Schedule(single_schedule=SingleSchedule(job_id="swupd-2c5d08c1-200a-49cf-b808-e53c74a22e86"))],
                    ),
                    ScheduledOperation(
                        operation=Operation(
                            post_operations=[],
                            pre_operations=[],
                            update_system_software_operation=SOTA_OPERATION_LARGE,
                        ),
                        schedules=[
                            Schedule(
                                repeated_schedule=RepeatedSchedule(
                                    job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d",
                                    cron_day_month="1",
                                    cron_day_week="2",
                                    cron_hours="*/3",
                                    cron_minutes="4",
                                    cron_month="5",
                                    duration=Duration(seconds=900),
                                )
                            )
                        ],
                    ),
                ]
            ),
            "1234",
            "<schedule_request>"
            "<request_id>1234</request_id>"
            "<update_schedule>"
            "<schedule><single_schedule>"
            "<job_id>swupd-2c5d08c1-200a-49cf-b808-e53c74a22e86</job_id>"
            "</single_schedule></schedule>"
            "<manifests><manifest_xml>"
            + escape(SOTA_OPERATION_SMALL_MANIFEST_XML)
            + "</manifest_xml></manifests>"
            "</update_schedule>"
            "<update_schedule>"
            "<schedule><repeated_schedule>"
            "<job_id>swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d</job_id>"
            "<duration>PT900S</duration>"
            "<cron_minutes>4</cron_minutes>"
            "<cron_hours>*/3</cron_hours>"
            "<cron_day_month>1</cron_day_month>"
            "<cron_month>5</cron_month>"
            "<cron_day_week>2</cron_day_week>"
            "</repeated_schedule></schedule>"
            "<manifests><manifest_xml>"
            + escape(SOTA_OPERATION_LARGE_MANIFEST_XML)
            + "</manifest_xml></manifests>"
            "</update_schedule>"
            "</schedule_request>",
        ),
    ],
)
def test_convert_update_scheduled_operations_to_xml_manifest_success(
    uso: UpdateScheduledOperations, request_id: str, expected_xml: str
):
    xml_manifest: str = convert_updated_scheduled_operations_to_dispatcher_xml(
        request_id, uso
    )
    assert xml_manifest == expected_xml


# Test cases to convert UpdateScheduledOperations -> dispatcher XML (exception)
@pytest.mark.parametrize(
    "uso, request_id, expected_exception, expected_exception_message",
    [
        (
            UpdateScheduledOperations(
                scheduled_operations=[
                    ScheduledOperation(
                        operation=Operation(
                            post_operations=[],
                            pre_operations=[PreOperation()],
                            update_system_software_operation=SOTA_OPERATION_LARGE,
                        ),
                        schedules=[Schedule(single_schedule=SingleSchedule(job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"))],
                    ),
                ]
            ),
            "1234",
            ValueError,
            "Pre-operations not supported",
        ),
        (
            UpdateScheduledOperations(
                scheduled_operations=[
                    ScheduledOperation(
                        operation=Operation(),
                        schedules=[Schedule(single_schedule=SingleSchedule(job_id="swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d"))],
                    ),
                ]
            ),
            "1234",
            ValueError,
            "Operation type not supported",
        ),
    ],
)
def test_convert_update_scheduled_operations_to_xml_manifest_exception(
    uso: UpdateScheduledOperations,
    request_id: str,
    expected_exception: Any,
    expected_exception_message: str,
):
    with pytest.raises(expected_exception) as exc_info:
        convert_updated_scheduled_operations_to_dispatcher_xml(request_id, uso)
    assert expected_exception_message == str(exc_info.value)

# Test cases for function that checks XML manifest creation from software update operations
@pytest.mark.parametrize(
    "operation, expected_xml",
    [
        (FOTA_OPERATION_SMALL, FOTA_OPERATION_SMALL_MANIFEST_XML),
        (FOTA_OPERATION_LARGE, FOTA_OPERATION_LARGE_MANIFEST_XML),
    ],
)
def test_convert_firmware_operation_to_xml_manifest_success(
    operation, expected_xml
):
    xml_manifest = convert_firmware_operation_to_xml_manifest(operation)
    assert xml_manifest == expected_xml

# Test cases for function that checks XML manifest creation from software update operations
@pytest.mark.parametrize(
    "operation, expected_xml",
    [
        (SOTA_OPERATION_LARGE, SOTA_OPERATION_LARGE_MANIFEST_XML),
        (SOTA_OPERATION_SMALL, SOTA_OPERATION_SMALL_MANIFEST_XML),
    ],
)
def test_convert_system_software_operation_to_xml_manifest_success(
    operation, expected_xml
):
    xml_manifest = convert_system_software_operation_to_xml_manifest(operation)
    assert xml_manifest == expected_xml


# Test cases for function that checks XML manifest creation from rpc activate operations
@pytest.mark.parametrize(
    "operation, rpc_expected_xml",
    [
        (RPC_OPERATION_LARGE, RPC_OPERATION_LARGE_MANIFEST_XML),
    ],
)
def test_convert_rpc_activate_operation_to_xml_manifest_success(
    operation, rpc_expected_xml
):
    rpc_xml_manifest = convert_rpc_activate_operation_to_xml_manifest(operation)
    assert rpc_xml_manifest == rpc_expected_xml


@pytest.mark.parametrize(
    "operation, exception_message",
    [
        (
            UpdateSystemSoftwareOperation(
                url="http://example.com/update",
                release_date=Timestamp(seconds=int(datetime(2023, 1, 1).timestamp())),
                do_not_reboot=False,
                package_list=["package1", "package2"],
            ),
            "Download mode cannot be unspecified",
        ),
    ],
)
def test_convert_system_software_operation_to_xml_manifest_unspecified_mode_error(
    operation, exception_message
):
    with pytest.raises(ValueError) as excinfo:
        convert_system_software_operation_to_xml_manifest(operation)
    assert exception_message in str(excinfo.value)


@pytest.mark.parametrize(
    "operation, expected_inner_xml",
    [
        (
            Operation(
                post_operations=[],
                pre_operations=[],
                update_system_software_operation=SOTA_OPERATION_SMALL,
            ),
            SOTA_OPERATION_SMALL_MANIFEST_XML,
        ),
    ],
)
def test_convert_operation_with_system_software_update_to_xml_manifests_success(
    operation, expected_inner_xml
):
    actual_result = convert_operation_to_xml_manifests(operation)

    expected_result = ET.Element('manifests')
    xml_manifest = ET.Element('manifest_xml')
    xml_manifest.text = expected_inner_xml
    expected_result.append(xml_manifest)

    assert ET.tostring(actual_result, encoding='unicode') == ET.tostring(
        expected_result, encoding='unicode')


@pytest.mark.parametrize(
    "operation, exception_message",
    [
        (
            Operation(
                post_operations=[],
                pre_operations=[PreOperation()],
                update_system_software_operation=SOTA_OPERATION_SMALL,
            ),
            "Pre-operations not supported",
        ),
        (
            Operation(
                post_operations=[PostOperation()],
                pre_operations=[PreOperation()],
                update_system_software_operation=SOTA_OPERATION_SMALL,
            ),
            "Pre-operations not supported",
        ),
        (
            Operation(
                post_operations=[PostOperation()],
                pre_operations=[],
                update_system_software_operation=SOTA_OPERATION_SMALL,
            ),
            "Post-operations not supported",
        ),
        (Operation(), "Operation type not supported"),
    ],
)
def test_convert_operation_with_invalid_operation_type_error(
    operation, exception_message
):
    with pytest.raises(ValueError) as excinfo:
        convert_operation_to_xml_manifests(operation)
    assert exception_message in str(excinfo.value)
