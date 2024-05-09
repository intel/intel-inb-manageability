import os
from unittest import TestCase

from inbm_lib.xmlhandler import XmlHandler

GOOD_SCHEDULED_XML = '''
<schedule_request>
  <request_id>1234</request_id>
  <update_schedule>
    <schedule>
      <single_schedule>
        <start_time>2023-03-01T08:00:00Z</start_time>
        <end_time>2023-03-01T12:00:00Z</end_time>
      </single_schedule>
    </schedule>
    <manifests>
      <manifest_xml>
        <![CDATA[<random><xml></xml></random>]]>
      </manifest_xml>
    </manifests>
  </update_schedule>
  <update_schedule>
    <schedule>
      <repeated_schedule>
        <duration>PT3600S</duration> <!-- Duration of 1 hour -->
        <cron_minutes>0</cron_minutes>
        <cron_hours>*/4</cron_hours> <!-- Every 4 hours -->
        <cron_day_month>*</cron_day_month>
        <cron_month>*</cron_month>
        <cron_day_week>*</cron_day_week>
      </repeated_schedule>
    </schedule>
    <manifests>
      <manifest_xml>
        <![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]>
      </manifest_xml>
      <manifest_xml>
        <![CDATA[<?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>]]>
      </manifest_xml>
    </manifests>
  </update_schedule>
</schedule_request>
'''

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
        self.good_schedule_xml = XmlHandler(GOOD_SCHEDULED_XML, is_file=False, schema_location=TEST_SCHEDULE_SCHEMA_LOCATION)

    def test_get_time_when_element_exists(self) -> None:
        self.assertEqual('\n        <?xml version="1" encoding="utf-8"?><manifest><type>ota</type><ota></ota></manifest>\n      ',
                 self.good_schedule_xml.get_element("update_schedule[2]/manifests/manifest_xml[2]"))
