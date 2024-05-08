import unittest
from unittest import TestCase

from inbm_lib.xmlhandler import XmlHandler, XmlException
import os

TEST_SCHEMA_LOCATION = os.path.join(
                                        os.path.dirname(__file__),
                                        '..',
                                        '..',
                                        '..',
                                        '..',
                                        'inbm',
                                        'dispatcher-agent',
                                        'fpm-template',
                                        'usr',
                                        'share',
                                        'dispatcher-agent',
                                        'manifest_schema.xsd',
                                    )

TEST_SCHEDULE_SCHEMA_LOCATION = os.path.join(
                                        os.path.dirname(__file__),
                                        '..',
                                        '..',
                                        '..',
                                        '..',
                                        'inbm',
                                        'dispatcher-agent',
                                        'fpm-template',
                                        'usr',
                                        'share',
                                        'dispatcher-agent',
                                        'schedule_manifest_schema.xsd',
                                    )

GOOD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
           '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
           'Sample FOTA manifest file</description><type>aota</type><repo>remote</repo>' \
           '</header><type><aota name="sample"><cmd>load</cmd><app>docker</app><fetch>sample</fetch>' \
           '<containerTag>defg</containerTag>' \
           '</aota></type></ota></manifest>'

ENTITY_INJECTION_XML = """<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [ <!ENTITY xxe 
SYSTEM "file:///etc/passwd"> ]><manifest><type>&xxe;</type><ota><header><id>sampleId</id>
<name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type>
<repo>remote</repo></header><type><aota name="sample-rpm"><cmd>load</cmd><app>docker</app>
<fetch>http://10.108.50.83/test_files/abcde/test-files-896/sample-container-load.tgz</fetch>
<containerTag>sample-container</containerTag></aota></type></ota></manifest>"""

BAD_VERSION_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
    'Sample FOTA manifest file</description><type>aota</type><repo>remote</repo>' \
    '</header><type><aota name="sample"><cmd>load</cmd><app>docker</app><fetch>sample</fetch>' \
    '<version>€</version><containerTag>defg</containerTag>' \
    '</aota></type></ota></manifest>'

# we used to test XML with a bad version number, but xmlschema doesn't seem to check this

BAD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
          '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
          'Sample AOTA manifest file<description><type>aota</type><repository>remote</repository>' \
          '</header><type><aota name="sample"><cmd>load</cmd><app>docker</app><fetch>sample</fetch>' \
          '<containerTag>defg</containerTag>' \
          '</aota></type></ota></manifest>'

INVALID_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
              'Sample AOTA manifest file</description><type>aota</type><repository>remote</repository>' \
              '</header><type><aota name="sample"><cmd>load</cmd>' \
              '<app>docker</app><fetch>sample</fetch>' \
              '<containerTag>defg</containerTag></aota></type><abc></abc></ota></manifest>'

EMPTY_TAG_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
                '<manifest><type>ota</type><ota><header><id>sampleId</id><name>Sample FOTA</name><description>' \
                'Sample AOTA manifest file</description><type>aota</type><repo>remote</repo>' \
                '</header><type><aota name="sample"><cmd>load</cmd><app>docker</app><fetch></fetch>' \
                '<containerTag>defg</containerTag>' \
                '</aota></type></ota></manifest>'

TEST_XML = '<?xml version="1.0" encoding="utf-8"?>' \
    '<manifest><type>ota</type><ota><header><id>sampleID</id><name>Sample FOTA</name><description>' \
    'Sample</description><type>fota</type><repo>remote</repo></header><type><fota name="sample">' \
    '<fetch>https://abc.tar</fetch><biosversion>2018.03</biosversion>' \
    '<vendor>Intel</vendor><manufacturer>hisilicon</manufacturer><product>kmb-on-poplar</product><releasedate>' \
    '2020-11-16</releasedate></fota></type></ota></manifest> '

GOOD_SCHEDULED_XML = '''<?xml version="1.0" encoding="utf-8"?>
<manifest>
	<type>schedule</type>
	<schedule>
		<singleSchedule>
			<start_time>2002-05-30T09:30:10</start_time>
			<end_time>2002-05-30T10:30:10</end_time>
			<tasks>
				<task>'
				    <?xml version="1.0" encoding="utf-8"?>
					<manifest>
						<type>ota</type>
						<ota>
							<header>
								<type>sota</type>
								<repo>remote</repo>
							</header>
							<type>
								<sota>
									<cmd logtofile="y">update</cmd>
									<mode>full</mode>
									<deviceReboot>no</deviceReboot>
								</sota>
							</type>
						</ota>
					</manifest>'
				</task>
			</tasks>
		</singleSchedule>
	</schedule>
</manifest>
'''

BAD_SCHEDULED_XML = '''<?xml version="1.0" encoding="utf-8"?>
<manifest>
	<type>schedule</type>
	<schedule>
		<singleSchedule>
			<tasks>
				<task>'
					<?xml version="1.0" encoding="utf-8"?>
					<manifest>
						<type>ota</type>
						<ota>
							<header>
								<type>sota</type>
								<repo>remote</repo>
							</header>
							<type>
								<sota>
									<cmd logtofile="y">update</cmd>
									<mode>full</mode>
									<deviceReboot>no</deviceReboot>
								</sota>
							</type>
						</ota>
					</manifest>'
				</task>
			</tasks>
		</singleSchedule>
	</schedule>
</manifest>
'''

class TestXmlParser(TestCase):

    def setUp(self) -> None:
        self.good = XmlHandler(GOOD_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.test = XmlHandler(TEST_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.good_schedule_xml = XmlHandler(GOOD_SCHEDULED_XML, is_file=False, schema_location=TEST_SCHEDULE_SCHEMA_LOCATION)
        self.bad_schedule_xml = XmlHandler(BAD_SCHEDULED_XML, is_file=False, schema_location=TEST_SCHEDULE_SCHEMA_LOCATION)

    def test_parser_creation_success(self) -> None:
        self.assertIsNotNone(self.good)

    def test_parser_creation_failure(self) -> None:
        with self.assertRaises(XmlException):
            XmlHandler(xml=BAD_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

    def test_aota_version_failure(self) -> None:
        with self.assertRaises(XmlException):
            XmlHandler(xml=BAD_VERSION_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

    def test_entity_injection(self) -> None:
        try:
            self.entity_injection_xmlhandler = XmlHandler(
                ENTITY_INJECTION_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
            self.fail("Expected an XmlException")
        except XmlException as e:
            # entity injection would insert /etc/passwd containing "root"
            self.assertFalse("root" in str(e))

            self.assertTrue("Forbidden" in str(e))

    def test_xsd_validation_failure(self) -> None:
        with self.assertRaises(XmlException):
            XmlHandler(xml=INVALID_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

    def test_empty_tag_failure1(self) -> None:
        try:
            parsed = XmlHandler(EMPTY_TAG_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
            parsed.get_children('ota/type/fetch')
        except XmlException as e:
            self.assertEqual("Cannot find children at specified path: ota/type/fetch", str(e))

    def test_empty_tag_failure2(self) -> None:
        try:
            parsed = XmlHandler(EMPTY_TAG_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
            parsed.get_children('ota/type/aota')
        except XmlException as e:
            self.assertEqual("Empty tag encountered. XML rejected", str(e))

    def test_empty_tag_allowed(self) -> None:
        parsed = XmlHandler(EMPTY_TAG_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        parsed.get_children('ota/type/aota')

    def test_get_element(self) -> None:
        self.assertEqual('sampleId', self.good.get_element('ota/header/id'))

    def test_get_children(self) -> None:
        self.assertEqual(
            {'app': 'docker', 'cmd': 'load', 'fetch': 'sample',
             'containerTag': 'defg', },
            self.good.get_children('ota/type/aota'))

    def test_set_attribute(self) -> None:
        self.assertEqual("remote", self.test.get_element("ota/header/repo"))
        self.test.set_attribute("ota/header/repo", "local")
        self.assertEqual("local", self.test.get_element("ota/header/repo"))

    def test_add_attribute(self) -> None:
        self.test.add_element("ota/type/fota", "path", "/new/path/added")
        self.assertEqual("/new/path/added", self.test.get_element("ota/type/fota/path"))

    def test_remove_element(self) -> None:
        self.assertEqual("Intel", self.test.get_element("ota/type/fota/vendor"))
        self.test.remove_element("ota/type/fota/vendor")
        self.assertRaises(XmlException, self.test.get_element, "ota/type/fota/vendor")

    def test_get_element_throws_exception(self) -> None:
        self.assertRaises(XmlException, self.good.get_element, 'ota/header/bb')

    def test_get_time_when_element_exists(self) -> None:
        self.assertTrue(self.good_schedule_xml.is_element_exist("schedule/singleSchedule/start_time"))

    def test_return_false_element_dne(self) -> None:
        self.assertFalse(self.bad_schedule_xml.is_element_exist("schedule/singleSchedule/start_time"))


if __name__ == '__main__':
    unittest.main()
