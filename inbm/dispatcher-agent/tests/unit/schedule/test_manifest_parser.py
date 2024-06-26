import os
from unittest import TestCase

from dispatcher.schedule.manifest_parser import ScheduleManifestParser
from inbm_lib.xmlhandler import XmlException

GOOD_IMMEDIATE_SCHEDULE_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>4324a262-b7d1-46a7-b8cc-84d934c3983f</request_id>
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

BAD_NO_SCHEDULED_REQUESTS_XML = """<?xml version="1.0" encoding="utf-8"?>
<schedule_request>
    <request_id>4324a262-b7d1-46a7-b8cc-84d934c3983f</request_id>
</schedule_request>"""

GOOD_SINGLE_SCHEDULED_NO_END_TIME_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>4324a262-b7d1-46a7-b8cc-84d934c3983f</request_id>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-939fe48c-32da-40eb-a00f-acfdb43a5d6d</job_id>
                <start_time>2024-01-01T00:00:00</start_time>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
</schedule_request>"""

GOOD_MULTIPLE_SCHEDULES_XML = """<?xml version="1.0" encoding="utf-8"?>
<schedule_request>
    <request_id>4324a262-b7d1-46a7-b8cc-84d934c3983f</request_id>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-f4d430a2-85b6-4653-8653-72ffce3f4c65</job_id>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
    <update_schedule>
        <schedule>        
            <single_schedule>
                <job_id>swupd-0d903fba-00b6-4daf-bf6f-964edf16988a</job_id>
                <start_time>2024-01-01T00:00:00</start_time>
                <end_time>2024-01-01T01:00:00</end_time>
            </single_schedule>
            <single_schedule>
                <job_id>swupd-88fff0ef-4fae-43a5-beb7-fe7d8d5e31cd</job_id>
                <start_time>2024-01-02T00:00:00</start_time>
            </single_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
       </manifests>
    </update_schedule>
    <update_schedule>
        <schedule>
            <single_schedule>
                <job_id>swupd-f02131f9-b7d9-4e3f-9ee2-615e0fe005a5</job_id>
                <start_time>2024-01-02T00:00:00</start_time>
                <end_time>2024-01-02T01:00:00</end_time>
            </single_schedule>
            <repeated_schedule>
                <job_id>swupd-4601c731-bce2-431a-bc3a-6aad5a091d4f</job_id>
                <duration>P7D</duration>
                <cron_minutes>0</cron_minutes>
                <cron_hours>0</cron_hours>
                <cron_day_month>*</cron_day_month>
                <cron_month>*</cron_month>
                <cron_day_week>*</cron_day_week>
            </repeated_schedule>
            <repeated_schedule>
                <job_id>swupd-9bc71491-45c3-4345-ae33-97e423f0dda9</job_id>
                <duration>P7D</duration>
                <cron_minutes>0</cron_minutes>
                <cron_hours>0</cron_hours>
                <cron_day_month>*</cron_day_month>
                <cron_month>*</cron_month>
                <cron_day_week>*</cron_day_week>
            </repeated_schedule>
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
</schedule_request>"""

SCHEDULE_SCHEMA_LOCATION = os.path.join(
    os.path.dirname(__file__),
    '..',
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
    '..',
    'fpm-template',
    'usr',
    'share',
    'dispatcher-agent',
    'manifest_schema.xsd',
)


class TestScheduleManifestParser(TestCase):

    def test_get_immediate_request_type(self) -> None:
        p = ScheduleManifestParser(GOOD_IMMEDIATE_SCHEDULE_XML,
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
        self.assertEqual(1, len(p.immedate_requests))
        self.assertEqual(1, len(p.immedate_requests[0].manifests))
        self.assertEqual(0, len(p.single_scheduled_requests))
        self.assertEqual(0, len(p.repeated_scheduled_requests))

    def test_get_multiple_scheduled_request_types(self) -> None:
        p = ScheduleManifestParser(GOOD_MULTIPLE_SCHEDULES_XML,
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
        self.assertEqual(1, len(p.immedate_requests))
        self.assertEqual(2, len(p.immedate_requests[0].manifests))
        self.assertEqual(3, len(p.single_scheduled_requests))
        self.assertEqual(2, len(p.single_scheduled_requests[0].manifests))
        self.assertEqual(2, len(p.repeated_scheduled_requests))
        self.assertEqual(3, len(p.repeated_scheduled_requests[0].manifests))

    def test_get_single_with_no_end_time(self) -> None:
        p = ScheduleManifestParser(GOOD_SINGLE_SCHEDULED_NO_END_TIME_XML,
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
        self.assertEqual(0, len(p.immedate_requests))
        self.assertEqual(1, len(p.single_scheduled_requests))
        self.assertEqual(1, len(p.single_scheduled_requests[0].manifests))
        self.assertEqual(0, len(p.repeated_scheduled_requests))

    def test_raise_exception_no_schedule_requests(self) -> None:
        with self.assertRaises(XmlException) as e:
            ScheduleManifestParser(BAD_NO_SCHEDULED_REQUESTS_XML,
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
