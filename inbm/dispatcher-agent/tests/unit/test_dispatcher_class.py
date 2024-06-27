import pytest
import os

from unit.common.mock_resources import *
from dispatcher.dispatcher_class import handle_updates

GOOD_IMMEDIATE_SCHEDULE_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>6bf587ac-1d70-4e21-9a15-097f6292b9c4</request_id>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d</job_id>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
</schedule_request>"""

GOOD_SEVERAL_IMMEDIATE_SCHEDULE_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>c9b74125-f3bb-440a-ad80-8d02090bd337</request_id>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d</job_id>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-88fff0ef-4fae-43a5-beb7-fe7d8d5e31cd</job_id>
                <start_time>2021-09-01T00:00:00</start_time>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-dea8fac4-dbdb-400e-ba11-4dd3c07ad270</job_id>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
</schedule_request>"""

SCHEDULE_SCHEMA_LOCATION = os.path.join(
    os.path.dirname(__file__),
    '..',
    '..',
    'fpm-template',
    'usr',
    'share',
    'dispatcher-agent',
    'schedule_manifest_schema.xsd',
)

EMBEDDED_SCHEMA_LOCATION = os.path.join(
    os.path.dirname(__file__),
    '..',
    '..',
    'fpm-template',
    'usr',
    'share',
    'dispatcher-agent',
    'manifest_schema.xsd',
)


@pytest.fixture
def mock_disp_obj():
    return MockDispatcher.build_mock_dispatcher()


@pytest.fixture
def method_counter(mocker):
    mock_method = mocker.patch.object(MockDispatcher, 'do_install')
    yield mock_method


def test_run_one_immediate_scheduled_manifest(mock_disp_obj, method_counter, mocker):
    # Mock the call to dispatcher.update_queue.get
    mocker.patch.object(mock_disp_obj.update_queue, 'get',
                        return_value=['schedule', GOOD_IMMEDIATE_SCHEDULE_XML, "REQ12345"])

    handle_updates(mock_disp_obj,
                   schedule_manifest_schema=SCHEDULE_SCHEMA_LOCATION,
                   manifest_schema=EMBEDDED_SCHEMA_LOCATION)

    # Assert that the do_install method is called once
    assert method_counter.call_count == 1


def test_run_several_immediate_scheduled_manifest(mock_disp_obj, method_counter, mocker):
    mocker.patch('dispatcher.schedule.sqlite_manager.SqliteManager.create_schedule')
    mocker.patch('dispatcher.schedule.sqlite_manager.SqliteManager.__init__', return_value=None)
    # Mock the call to dispatcher.update_queue.get
    mocker.patch.object(mock_disp_obj.update_queue, 'get',
                        return_value=['schedule', GOOD_SEVERAL_IMMEDIATE_SCHEDULE_XML, "REQ12345"])

    handle_updates(mock_disp_obj,
                   schedule_manifest_schema=SCHEDULE_SCHEMA_LOCATION,
                   manifest_schema=EMBEDDED_SCHEMA_LOCATION)

    # Assert that the do_install method is called the correct number of times
    assert method_counter.call_count == 2
