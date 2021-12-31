import os
from unittest import TestCase
from inbm_vision_lib.xml_handler import XmlHandler, XmlException
from inbm_vision_lib.ota_parser import ParseException, get_children, parse_pota

MISSING_HEADER_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>ota</type>' \
    '<ota><type><fota name="sample"><targets><target>123ABC</target></targets>' \
    '<biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor>  ' \
    '<manufacturer>Default string</manufacturer><product>Default string</product>                 ' \
    '<releasedate>2018-03-30</releasedate>             ' \
    '<path>/var/cache/manageability/X041_BIOS.tar</path>          ' \
    '</fota></type></ota> </manifest>'

POTA_GOOD_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>' \
                     '<type>pota</type><repo>local</repo></header><type><pota><targetType>node</targetType>' \
                     '<targets><target>None</target></targets><fota name="sample"><biosversion>5.12</biosversion>' \
                     '<manufacturer>intel</manufacturer><product>kmb-hddl2</product><vendor>Intel</vendor>' \
                     '<releasedate>2021-12-25</releasedate>' \
                     '<path>/var/cache/manageability/repository-tool/test_fota</path></fota><sota>' \
                     '<cmd logtofile="y">update</cmd><release_date>2021-12-25</release_date>' \
                     '<path>/var/cache/manageability/repository-tool/test_sota</path></sota>' \
                     '</pota></type></ota></manifest>'

PARSED_POTA = {'biosversion': '5.12',
                 'cmd': 'update',
                 'fota_path': '/var/cache/manageability/repository-tool/test_fota',
                 'fota_signature': None,
                 'logtofile': 'y',
                 'manufacturer': 'intel',
                 'product': 'kmb-hddl2',
                 'release_date': '2021-12-25',
                 'releasedate': '2021-12-25',
                 'sota_path': '/var/cache/manageability/repository-tool/test_sota',
                 'sota_signature': None,
                 'vendor': 'Intel'}

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    './vision_manifest_schema.xsd')


class TestManParser(TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    def test_missing_header_throws(self):
        with self.assertRaises(ParseException):
            get_children(XmlHandler(MISSING_HEADER_XML), 'ota/header')

    def test_parse_pota_pass(self):
        parsed = XmlHandler(xml=POTA_GOOD_MANIFEST, schema_location=TEST_SCHEMA_LOCATION)
        parsed_dict = parse_pota(parsed, 'ota/type/pota')
        self.assertEqual(parsed_dict, PARSED_POTA)
