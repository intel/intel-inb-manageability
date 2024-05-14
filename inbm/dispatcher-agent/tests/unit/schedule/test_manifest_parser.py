import os
from unittest import TestCase

from inbm_lib.xmlhandler import XmlHandler

GOOD_IMMEDIATE_SINGLE_SOTA_XML = '''<schedule_request><request_id>REQ12345</request_id>
    <update_schedule>
      <schedule>
        <single_schedule></single_schedule>
      </schedule>
      <manifests>
        <manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
      </manifests>
  </update_schedule></schedule_request>'''
  
GOOD_REPEATED_SINGLE_SOTA_XML = '''<schedule_request><request_id>REQ12345</request_id>
    <update_schedule>
      <schedule>
        <repeated_schedule>
          <duration>P7D</duration>
          <cron_minutes>15</cron_minutes>
          <cron_hours>22</cron_hours>
          <cron_day_month>*</cron_day_month>
          <cron_month>*</cron_month>
          <cron_day_week>*</cron_day_week>
        </repeated_schedule>
      </schedule>
      <manifests>
        <manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
      </manifests>
  </update_schedule></schedule_request>'''
  
BAD_BOTH_SINGLE_AND_REPEATED_XML = '''<schedule_request><request_id>REQ12345</request_id>
    <update_schedule><schedule><single_schedule></single_schedule><repeated_schedule><duration></repeated_schedule></schedule><manifests><manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
    </manifests></update_schedule><update_schedule><schedule><single_schedule></single_schedule>
    </schedule><manifests><manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
    </manifests></update_schedule></schedule_request>'''
    
GOOD_MULTIPLE_MANIFEST_SINGLE_SCHEDULED_IMMEDIATE_REQUEST_XML = '''<schedule_request><request_id>REQ12345</request_id>
    <update_schedule><schedule><single_schedule></single_schedule></schedule><manifests><manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
    </manifests></update_schedule><update_schedule><schedule><single_schedule></single_schedule>
    </schedule><manifests><manifest_xml><![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]></manifest_xml>
    </manifests></update_schedule></schedule_request>'''

TEST_SCHEDULE_SCHEMA_LOCATION = os.path.join(
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

class TestManifestParser(TestCase):
    def setUp(self) -> None:
        self.good_multiple_scheduled_requests = XmlHandler(GOOD_MULTIPLE_MANIFEST_SINGLE_SCHEDULED_IMMEDIATE_REQUEST_XML, is_file=False, schema_location=TEST_SCHEDULE_SCHEMA_LOCATION)

    def test_get_all_scheduled_requests(self) -> None:
        schedules = self.good_multiple_scheduled_requests.find_elements('update_schedule')
        self.assertEqual(2, len(schedules))
     
