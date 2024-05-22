import os
from unittest import TestCase

from dispatcher.schedule.manifest_parser import ScheduleManifestParser
from dispatcher.dispatcher_exception import DispatcherException
from inbm_lib.xmlhandler import XmlException

GOOD_IMMEDIATE_SCHEDULE_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>REQ12345</request_id>
    <update_schedule>
        <schedule>
            <single_schedule />
        </schedule>
        <manifests>
            <manifest_xml><![CDATA[<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd><mode>full</mode><deviceReboot>no</deviceReboot>
                </sota></type></ota></manifest>]]></manifest_xml>
        </manifests>
    </update_schedule>
</schedule_request>"""

BAD_NO_SCHEDULED_REQUESTS_XML = """<?xml version="1.0" encoding="utf-8"?>
<schedule_request>
    <request_id>REQ12345</request_id>
</schedule_request>"""

GOOD_SINGLE_SCHEDULED_NO_END_TIME_XML = """<?xml version="1" encoding="utf-8"?>
<schedule_request>
    <request_id>REQ12345</request_id>
    <update_schedule>
        <schedule>
            <single_schedule>
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
    <request_id>REQ12345</request_id>
    <update_schedule>
        <schedule>
            <single_schedule />
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
                <start_time>2024-01-01T00:00:00</start_time>
                <end_time>2024-01-01T01:00:00</end_time>
            </single_schedule>
            <single_schedule>
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
                <start_time>2024-01-02T00:00:00</start_time>
                <end_time>2024-01-02T01:00:00</end_time>
            </single_schedule>
            <repeated_schedule>
                <duration>P7D</duration>
                <cron_minutes>0</cron_minutes>
                <cron_hours>0</cron_hours>
                <cron_day_month>*</cron_day_month>
                <cron_month>*</cron_month>
                <cron_day_week>*</cron_day_week>
            </repeated_schedule>
            <repeated_schedule>
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
        self.assertEqual("REQ12345", p.request_id)
        self.assertEqual(1, len(p.immedate_requests))
        self.assertEqual(1, len(p.immedate_requests[0].manifests))
        self.assertEqual(0, len(p.single_scheduled_requests))
        self.assertEqual(0, len(p.repeated_scheduled_requests))
        
    def test_get_multiple_scheduled_request_types(self) -> None:
        p = ScheduleManifestParser(GOOD_MULTIPLE_SCHEDULES_XML, 
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
        self.assertEqual("REQ12345", p.request_id)
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
        self.assertEqual("REQ12345", p.request_id)
        self.assertEqual(0, len(p.immedate_requests))
        self.assertEqual(1, len(p.single_scheduled_requests))
        self.assertEqual(1, len(p.single_scheduled_requests[0].manifests))
        self.assertEqual(0, len(p.repeated_scheduled_requests))

    def test_raise_exception_no_schedule_requests(self) -> None:
        with self.assertRaises(XmlException) as e:
            ScheduleManifestParser(BAD_NO_SCHEDULED_REQUESTS_XML, 
                                   schedule_schema_location=SCHEDULE_SCHEMA_LOCATION,
                                   embedded_schema_location=EMBEDDED_SCHEMA_LOCATION)
            
    