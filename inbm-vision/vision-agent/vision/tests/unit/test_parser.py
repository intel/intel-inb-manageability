
import datetime
from unittest import TestCase
from mock import Mock, patch
from vision.constant import VisionException
from vision.parser import XLinkParser
from inbm_vision_lib.xml_handler import XmlHandler
from inbm_vision_lib.constants import XmlException


MISSING_HEADER_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>ota</type>' \
    '<ota><type><fota name="sample"><targets><target>123ABC</target></targets>' \
    '<biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor>  ' \
    '<manufacturer>Default string</manufacturer><product>Default string</product>                 ' \
    '<releasedate>2018-03-30</releasedate>             ' \
    '<path>/var/cache/manageability/X041_BIOS.tar</path>          ' \
    '</fota></type></ota> </manifest>'


REVISED_VALUE = '<?xml version="1.0" encoding="utf-8"?><manifest>    <type>ota</type>    <ota>   ' \
                '     <header>' \
                '<type>fota</type>' \
                '            <repo>local</repo>        </header>        <type>            <fota ' \
                'name="sample">' \
                '                <fetch>/var/cache/manageability/X041_BIOS.tar</fetch>' \
                '                <biosversion>5.12</biosversion>' \
                '                <vendor>American Megatrends Inc.</vendor>                ' \
                '<manufacturer>Default string</manufacturer>                <product>Default ' \
                'string</product>' \
                '                <releasedate>2018-03-30</releasedate>' \
                '                <tooloptions>/p /b</tooloptions>            </fota>        ' \
                '</type>' \
                '    </ota></manifest>'

NODE_REGISTRATION_XML = '<?xml version="1.0" encoding="utf-8"?>' \
                        '<message>' \
                        '    <register id="123ABC">' \
                        '        <items>' \
                        '           <bootFwDate>10-9-2018</bootFwDate>' \
                        '           <bootFwVendor>Dell Inc.</bootFwVendor>' \
                        '           <bootFwVersion>1.5.9</bootFwVersion>' \
                        '           <osType>Linux</osType>' \
                        '           <osVersion>Ubuntu 16.04.6 LTS</osVersion>' \
                        '           <osReleaseDate>10-09-2020</osReleaseDate>' \
                        '           <manufacturer>Dell Inc.</manufacturer>' \
                        '           <dmVerityEnabled>False</dmVerityEnabled>' \
                        '           <measuredBootEnabled>UNKNOWN</measuredBootEnabled>' \
                        '           <flashless>false</flashless>' \
                        '           <stepping>A0</stepping>' \
                        '           <is_xlink_secure>false</is_xlink_secure>' \
                        '           <sku>3400VE</sku>' \
                        '           <model>Intel Keem Bay HDDL2</model>' \
                        '           <product>intel</product>' \
                        '           <serialNumber>c0428202080d709</serialNumber>' \
                        '           <version>bit-creek-2.13.2-r1.aarch64</version>' \
                        '       </items>' \
                        '   </register>' \
                        '</message>' \

NODE_REGISTRATION_XML_EMPTY_BOOT_FW_DATE = '<?xml version="1.0" encoding="utf-8"?><message>    <register ' \
    'id="123ABC">        <items>' \
    '            <bootFwDate>None</bootFwDate>            ' \
    '<bootFwVendor>Dell Inc.</bootFwVendor>            ' \
    '<bootFwVersion>1.5.9</bootFwVersion>' \
    '            <osType>Linux</osType>            <osVersion>Ubuntu 16.04.6 ' \
    'LTS</osVersion> ' \
    '           <manufacturer>Dell Inc.</manufacturer>        '\
    '<dmVerityEnabled>False</dmVerityEnabled>            <measuredBootEnabled>UNKNOWN</measuredBootEnabled>' \
    '            <flashless>false</flashless>' \
    '   </items>    ' \
    '</register></message>'

NODE_HEARTBEAT_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <heartbeat ' \
                     'id="123ABC"/></message>'
NODE_DOWNLOAD_STATUS_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <downloadStatus ' \
                           'id="123ABC">   ' \
                           '     <items>            <status>True</status>        </items>    ' \
                           '</downloadStatus></message>'
NODE_SEND_FILE_RESPONSE_XML = '<?xml version="1.0" encoding="utf-8"?><message>    ' \
                              '<sendFileResponse id="123ABC"> ' \
                              '       <items>            <sendDownload>True</sendDownload>       ' \
                              ' </items>   ' \
                              ' </sendFileResponse></message>'
# NODE_OTA_RESULT_XML =
TELEMETRY_EVENT_XML = '<?xml version="1.0" encoding="utf-8"?><message>    ' \
    '<telemetryEvent id="123ABC"> ' \
    '       <items>            <telemetryMessage>Rebooting platform</telemetryMessage>   ' \
    ' </items>   ' \
    ' </telemetryEvent></message>'

CONFIG_RESPONSE_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <configResponse id="123ABC">' \
                      '        <items>            <configMessage>' \
                      ' {"status": 400, "message": "NODE Configuration command: FAILED"}</configMessage>' \
                      '        </items>    </configResponse></message>'

UNSUPPORTED_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <sendFeedback id="123ABC"> ' \
                  '' \
                  '       <items>            <sendDownload>True</sendDownload>        </items>   ' \
                  '' \
                  ' </sendFeedback></message>'

NO_NID_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <sendFileResponse>' \
             '       <items>            <sendDownload>True</sendDownload>        </items>   ' \
             ' </sendFileResponse></message>'


NODE_REGISTRATION_INFORMATION = {
    'bootFwDate': datetime.datetime(2018, 10, 9, 0, 0), 'bootFwVersion': '1.5.9',
    'bootFwVendor': 'Dell Inc.', 'osType': 'Linux', 'osVersion': 'Ubuntu 16.04.6 LTS',
    'osReleaseDate': datetime.datetime(2020, 10, 9, 0, 0),
    'manufacturer': 'Dell Inc.',
    'dmVerityEnabled': 'False',
    'measuredBootEnabled': 'UNKNOWN',
    'flashless': False,
    'is_xlink_secure': False,
    'stepping': 'A0',
    'sku': '3400VE',
    'model': 'Intel Keem Bay HDDL2',
    'product': 'intel',
    'serialNumber': 'c0428202080d709',
    'version': 'bit-creek-2.13.2-r1.aarch64'}

SEND_DOWNLOAD_STATUS = {'sendDownload': 'True'}
DOWNLOAD_STATUS = {"status": 'True'}
TELEMETRY_EVENT = {"telemetryMessage": "Rebooting platform"}
CONFIG_RESPONSE_MESSAGE = {
    'item': ' {"status": 400, "message": "NODE Configuration command: FAILED"}'}


class TestXLinkParser(TestCase):

    def setUp(self) -> None:
        self.parser = XLinkParser()

    def test_parse_NODE_REGISTRATION_XML(self):
        command_type, sid, dictionary = self.parser.parse(NODE_REGISTRATION_XML)
        self.assertEqual(command_type, "register")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, NODE_REGISTRATION_INFORMATION)

    def test_parse_NODE_HEARTBEAT_XML(self):
        command_type, sid, dictionary = self.parser.parse(NODE_HEARTBEAT_XML)
        self.assertEqual(command_type, "heartbeat")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, None)

    def test_parse_NODE_DOWNLOAD_STATUS_XML(self):
        command_type, sid, dictionary = self.parser.parse(NODE_DOWNLOAD_STATUS_XML)
        self.assertEqual(command_type, "downloadStatus")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, DOWNLOAD_STATUS)

    def test_parse_NODE_SEND_FILE_RESPONSE_XML(self):
        command_type, sid, dictionary = self.parser.parse(NODE_SEND_FILE_RESPONSE_XML)
        self.assertEqual(command_type, "sendFileResponse")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, SEND_DOWNLOAD_STATUS)

    def test_parse_unsupported_command_type(self):
        self.assertRaises(ValueError, self.parser.parse, UNSUPPORTED_XML)

    def test_parse_empty_sid_in_xml(self):
        self.assertRaises(ValueError, self.parser.parse, NO_NID_XML)

    def test_parse_telemetry_event(self) -> None:
        command_type, nid, dictionary = self.parser.parse(TELEMETRY_EVENT_XML)
        self.assertEqual(command_type, "telemetryEvent")
        self.assertEqual(nid, "123ABC")
        self.assertEqual(dictionary, TELEMETRY_EVENT)

    def test_config_response(self) -> None:
        command_type, nid, dictionary = self.parser.parse(CONFIG_RESPONSE_XML)
        self.assertEqual(command_type, "configResponse")
        self.assertEqual(nid, "123ABC")
        self.assertEqual(dictionary, CONFIG_RESPONSE_MESSAGE)

    def test_check_command_type_fail(self) -> None:
        self.assertRaises(VisionException, self.parser._check_command_type)

    def test_check_node_id_fail(self) -> None:
        self.assertRaises(VisionException, self.parser._check_node_id)

    def test_parse_node_registration_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_node_registration)

    def test_parse_node_registration_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_node_registration)

    def test_parse_node_registration_empty_boot_fw_date(self) -> None:
        self.parser._xml_handler = XmlHandler(NODE_REGISTRATION_XML_EMPTY_BOOT_FW_DATE)
        self.parser.command_type = "register"  # type: ignore
        self.assertRaises(XmlException, self.parser._parse_node_registration)  # type: ignore

    @patch('vision.parser.XLinkParser._is_valid_node_registration', return_value=False)
    def test_parse_node_registration_validate_fail(self, validate) -> None:
        self.parser._xml_handler = XmlHandler(NODE_REGISTRATION_XML)
        self.parser.command_type = "register"  # type: ignore
        self.assertRaises(XmlException, self.parser._parse_node_registration)  # type: ignore
        validate.assert_called_once()

    def test_parse_download_status_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_download_status)

    def test_parse_download_status_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_download_status)

    def test_parse_send_file_response_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_send_file_response)

    def test_parse_send_file_response_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_send_file_response)

    def test_parse_ota_result_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_ota_result)

    def test_parse_ota_result_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_ota_result)

    def test_parse_telemetry_event_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_telemetry_event)

    def test_parse_telemetry_event_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_telemetry_event)

    def test_parse_config_response_empty_xml(self) -> None:
        self.assertRaises(VisionException, self.parser._parse_config_response)

    def test_parse_config_response_empty_command_type(self) -> None:
        self.parser._xml_handler = Mock()
        self.assertRaises(VisionException, self.parser._parse_config_response)
