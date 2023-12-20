"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os

import pytest
from dispatcher.common.result_constants import Result
from dispatcher.source.constants import ApplicationRemoveSourceParameters, OsType, SourceParameters
from dispatcher.source.source_command import do_source_command
from inbm_lib.xmlhandler import XmlHandler

TEST_SCHEMA_LOCATION = os.path.join(
    os.path.dirname(__file__),
    "../../../fpm-template/usr/share/dispatcher-agent/" "manifest_schema.xsd",
)


@pytest.fixture
def xml_handler_factory():
    def _factory(xml):
        return XmlHandler(xml=xml, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

    return _factory


@pytest.mark.parametrize(
    "xml,patch_target,return_value,expected_message",
    [
        (
            """<?xml version="1.0" encoding="utf-8"?>
            <manifest>
                <type>source</type>
                <osSource><list/></osSource>
            </manifest>""",
            "dispatcher.source.source_command.create_os_source_manager",
            ["source1", "source2"],
            '["source1", "source2"]',
        ),
        (
            """<?xml version="1.0" encoding="utf-8"?>
            <manifest>
                <type>source</type>
                <applicationSource><list/></applicationSource>
            </manifest>""",
            "dispatcher.source.source_command.create_application_source_manager",
            {"foo.list": ["source1", "source2"]},
            '{"foo.list": ["source1", "source2"]}',
        ),
    ],
)
def test_do_source_command_list(
    mocker, xml_handler_factory, xml, patch_target, return_value, expected_message
):
    xml_handler = xml_handler_factory(xml)

    mock_source_manager = mocker.Mock()
    mock_source_manager.list.return_value = return_value

    mocker.patch(patch_target, return_value=mock_source_manager)

    result = do_source_command(xml_handler, OsType.Ubuntu)

    assert result == Result(status=200, message=expected_message)
    mock_source_manager.list.assert_called_once()


@pytest.mark.parametrize(
    "xml, manager_mock, os_type, expected_call",
    [
        (
            """<?xml version="1.0" encoding="utf-8"?>
            <manifest>
                <type>source</type>
                <osSource><remove><repos><source_pkg>source1</source_pkg>
                                        <source_pkg>source2</source_pkg></repos></remove></osSource>
            </manifest>""",
            "dispatcher.source.source_command.create_os_source_manager",
            OsType.Ubuntu,
            SourceParameters(sources=["source1", "source2"]),
        ),
        (
            """<?xml version="1.0" encoding="utf-8"?>
            <manifest>
                <type>source</type>
                <applicationSource><remove><gpg><keyid>46C1680FC119E61A501811823A319F932D945953</keyid></gpg>
                                        <repo><filename>intel-gpu-jammy.list</filename></repo>
                                </remove></applicationSource>
            </manifest>""",
            "dispatcher.source.source_command.create_application_source_manager",
            OsType.Ubuntu,
            ApplicationRemoveSourceParameters(
                gpg_key_id="46C1680FC119E61A501811823A319F932D945953",
                file_name="intel-gpu-jammy.list",
            ),
        ),
    ],
)
def test_do_source_command_remove(
    mocker, xml_handler_factory, xml, manager_mock, os_type, expected_call
):
    xml_handler = xml_handler_factory(xml)

    mock_manager = mocker.Mock()
    mock_manager.remove.return_value = None

    mocker.patch(manager_mock, return_value=mock_manager)

    result = do_source_command(xml_handler, os_type)

    mock_manager.remove.assert_called_once_with(expected_call)
    assert result == Result(status=200, message="SUCCESS")
