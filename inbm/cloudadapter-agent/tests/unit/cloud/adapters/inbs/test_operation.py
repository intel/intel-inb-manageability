"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import pytest
from cloudadapter.pb.common.v1.common_pb2 import (
    UpdateSystemSoftwareOperation,
    Operation,
    PreOperation,
    PostOperation,
)
from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime

# Import the function to be tested
from cloudadapter.cloud.adapters.inbs.operation import (
    convert_system_software_operation_to_xml_manifest,
    convert_operation_to_xml_manifests,
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
    "<manifest><ota><header><type>sota</type><repo>remote</repo></header>"
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
    "<manifest><ota><header><type>sota</type><repo>remote</repo></header>"
    "<type><sota>"
    '<cmd logtofile="y">update</cmd>'
    "<mode>full</mode>"
    "<deviceReboot>yes</deviceReboot>"
    "</sota></type>"
    "</ota></manifest>"
)


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
    "operation, num_manifests, expected_xml",
    [
        (
            Operation(
                post_operations=[],
                pre_operations=[],
                update_system_software_operation=SOTA_OPERATION_SMALL,
            ),
            1,
            SOTA_OPERATION_SMALL_MANIFEST_XML,
        ),
    ],
)
def test_convert_operation_with_system_software_update_to_xml_manifests_success(
    operation, num_manifests, expected_xml
):
    manifests = convert_operation_to_xml_manifests(operation)
    assert len(manifests) == num_manifests
    assert manifests[0] == expected_xml


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
