import os
from unittest import TestCase

from inbm_vision_lib.xml_handler import XmlHandler, XmlException
from typing import Dict, Any
from mock import patch
from inbm_vision_lib.path_prefixes import INBM_VISION_CACHE_PATH_PREFIX

GOOD_VISION_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>ota</type>     ' \
                  '<ota>         <header> ' \
                  '            <id>sampleId</id>             <name>Sample FOTA</name>       ' \
                  '      <description>Sample FOTA manifest file</description>             ' \
                  '<type>fota</type>   ' \
                  '         <repo>local</repo>         </header>         <type>             ' \
                  '<fota name="sample">  ' \
                  '<targetType>node</targetType>' \
                  '               <targets>                     <target>123ABC</target>          ' \
                  '                    ' \
                  '        </targets>                 ' \
                  '<biosversion>5.12</biosversion>                 <vendor>American ' \
                  'Megatrends Inc.</vendor>  ' \
                  '               <manufacturer>Default string</manufacturer>      ' \
                  '           <product>Default string</product>                 ' \
                  '<releasedate>2018-03-30</releasedate>             ' \
                  '<path>"$INBM_VISION_CACHE_PATH_PREFIX"/"X041_BIOS.tar")</path>          ' \
                  '</fota></type></ota> </manifest>'

EMPTY_TARGET_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>ota</type>     ' \
    '<ota>         <header> ' \
    '            <id>sampleId</id>             <name>Sample FOTA</name>       ' \
    '      <description>Sample FOTA manifest file</description>             ' \
    '<type>fota</type>   ' \
    '         <repo>local</repo>         </header>         <type>             ' \
    '<fota name="sample">  ' \
    '<targetType>node</targetType>' \
    '               <targets>                     <target></target>          ' \
    '                    ' \
    '        </targets>                 ' \
    '<biosversion>5.12</biosversion>                 <vendor>American ' \
    'Megatrends Inc.</vendor>  ' \
    '               <manufacturer>Default string</manufacturer>      ' \
    '           <product>Default string</product>                 ' \
    '<releasedate>2018-03-30</releasedate>             ' \
    '<path>"$INBM_VISION_CACHE_PATH_PREFIX"/"X041_BIOS.tar"</path>          ' \
    '</fota></type></ota> </manifest>'

BAD_VISION_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>ota</type>     ' \
                 '<ota>         <header>' \
                 '             <id>sampleId</id>             <name>Sample FOTA</name>' \
                 '             <descrip>Sample FOTA manifest file</description>    ' \
                 '         <type></type>             <repo>local</repo>     ' \
                 '    </header>         <type>             <fota name="sample">     ' \
                 '            <targets>                     <target>slave-id1</target>     ' \
                 '                <target>slave-id2</target>                     ' \
                 '<target>vision-id</target>     ' \
                 '            </targets>                ' \
                 '                <biosversion>1.0</biosversion>   ' \
                 '              <vendor>American Megatrends Inc.</vendor>  ' \
                 '               <manufacturer>Default string</manufacturer>   ' \
                 '              <product>Default string</product>            ' \
                 '     <releasedate>2018-03-30</releasedate>              ' \
                 '   <path>/var/cache/repository-tool</path>       ' \
                 '      </fota>         </type>     </ota> </manifest>'

EMPTY_TAG_VISION_XML = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>' \
                       '<id>sampleId</id><name>Sample FOTA</name><description>Sample FOTA manifest file' \
                       '</description><type>fota</type><repo>local</repo></header><type><fota name="sample">' \
                       '<targetType>host</targetType><targets><target>123ABC</target></targets><biosversion>' \
                       '</biosversion><vendor>American Megatrends Inc.</vendor><manufacturer>Default string' \
                       '</manufacturer><product>Default string</product><releasedate>2018-03-30</releasedate>' \
                       '<path>"$INBM_VISION_CACHE_PATH_PREFIX"/"X041_BIOS.tar"</path></fota></type></ota></manifest>'

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    './vision_manifest_schema.xsd')


class TestXmlHandler(TestCase):

    def setUp(self) -> None:
        self.good = XmlHandler(GOOD_VISION_XML, schema_location=TEST_SCHEMA_LOCATION)
        self.empty_xml = XmlHandler(EMPTY_TAG_VISION_XML, schema_location=TEST_SCHEMA_LOCATION)
        self.empty_target_xml = XmlHandler(EMPTY_TARGET_XML, schema_location=TEST_SCHEMA_LOCATION)

    def test_parser_creation_success(self):
        self.assertIsNotNone(self.good)

    def test_raises_when_schema_file_not_exist(self):
        with self.assertRaises(XmlException):
            XmlHandler(GOOD_VISION_XML, schema_location='/etc/schema.xsd')

    @patch('os.path.islink', return_value=True)
    def test_raises_when_schema_file_is_symlink(self, mock_islink):
        with self.assertRaises(XmlException):
            self.good._validate_schema()

    def test_get_children_successfully(self):
        expected_children: Dict[str, Any] = {"id": 'sampleId',
                                             "name": 'Sample FOTA',
                                             "description": "Sample FOTA manifest file",
                                             "type": 'fota',
                                             "repo": 'local'}

        children = self.good.get_children('ota/header')
        self.assertEquals(expected_children, children)

    def test_parser_creation_xml_none_success(self):
        self.assertIsNotNone(XmlHandler)

    def test_get_element(self):
        self.assertEquals('ota',
                          self.good.get_element('type'))

    def test_get_element_throws_exception(self):
        self.assertRaises(XmlException, self.good.get_element, 'fota/manufacturer/abc')

    def test_get_children_empty_tag_throws_exception(self):
        self.assertRaises(XmlException, self.empty_xml.get_children, 'ota/type/fota')

    def test_get_children_empty_root_throws_exception(self):
        self.empty_xml._root = None
        self.assertRaises(XmlException, self.empty_xml.get_children, 'ota/type/fota')

    def test_get_multiple_children_empty_tag_returns_empty_list(self):
        c, e = self.empty_target_xml.get_multiple_children('ota/type/fota/targets')
        self.assertEquals(c, {})
        self.assertEquals(e, 0)
