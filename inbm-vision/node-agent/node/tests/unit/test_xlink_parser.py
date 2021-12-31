
from unittest import TestCase

from node.constant import *
from node.xlink_parser import XLinkParser
from inbm_vision_lib.xml_handler import XmlException
from mock import patch, Mock
from node.node_exception import NodeException

REQUEST_TO_DOWNLOAD_XML = '<?xml version="1.0" encoding="utf-8"?>' \
                          '<message>' \
                          '    <requestToDownload id="123ABC">' \
                          '        <items>' \
                          '            <size_kb>765982</size_kb>' \
                          '        </items>' \
                          '    </requestToDownload>' \
                          '</message>'

REGISTER_RESPONSE_XML = '<?xml version="1.0" encoding="utf-8"?>' \
                        '<message>' \
                        '    <registerResponse id="123ABC">' \
                        '        <heartbeatIntervalSecs>20</heartbeatIntervalSecs>' \
                        '    </registerResponse>' \
                        '</message>'

RESTART_XML = '<?xml version="1.0" encoding="utf-8"?>' \
              '<manifest>' \
              '   <type>cmd</type>' \
              '   <cmd>restart</cmd>' \
              '</manifest>'

REQUEST_IS_ALIVE_XML = '<?xml version="1.0" encoding="utf-8"?>' \
                       '<message>' \
                       '    <isAlive id="123ABC"/>' \
                       '</message>'

INVALID_XML = '<?xml version="1.0" encoding="utf-8"?>' \
              '<message>' \
              '    <registerResponse id="123ABC">' \
              '        <heartbeatIntervalSecs><heartbeatIntervalSecs>' \
              '    </registerResponse>' \
              '</message>'

GET_ELEMENT_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <getConfigValues id="389C0A">        ' \
                  '<targetType>node</targetType>        <items>            <key>registrationRetryTimerSecs</key>   ' \
                  '  </items>    </getConfigValues></message> '

SET_ELEMENT_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <setConfigValues id="389C0A">        ' \
                  '<targetType>node</targetType>        <items>            <key>registrationRetryTimerSecs:30</key> ' \
                  '  </items>    </setConfigValues></message> '

MISSING_NID_XML = '<?xml version="1.0" encoding="utf-8"?><message>    <getConfigValues id="">        ' \
                  '<targetType>node</targetType>        <items>            <key>registrationRetryTimerSecs</key>  ' \
                  '  </items>    </getConfigValues></message> '

LOAD_XML = '<?xml version="1.0" encoding="utf-8"?>' \
           '<message>' \
           '    <configRequest id="389C0A">' \
           '        <items>' \
           '            <manifest>' \
           '                <type>config</type>' \
           '                <config>' \
           '                    <cmd>load</cmd>' \
           '                    <targetType>node_client</targetType>' \
           '                    <configtype>' \
           '                        <load>' \
           '                            <path>/var/cache/manageability/intel_manageability_node.conf</path>' \
           '                        </load>' \
           '                    </configtype>' \
           '                </config>' \
           '            </manifest>' \
           '        </items>' \
           '    </configRequest>' \
           '</message>'

FOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
    '<message>' \
    '<otaUpdate id="389C0A">' \
    '<items>' \
    '<manifest>' \
    '<type>ota</type>' \
    '<ota>' \
    '<header>' \
    '<type>fota</type>' \
    '<repo>local</repo>' \
    '</header>' \
    '<type>' \
    '<fota name="sample">' \
    '<path>/var/cache/manageability/X041_BIOS.tar</path>' \
    '<biosversion>5.12</biosversion>' \
    '<vendor>Dell Inc.</vendor>' \
    '<manufacturer>Dell Inc.</manufacturer>' \
    '<product>Aptio CRB</product>' \
    '<releasedate>2019-12-29</releasedate>' \
    '</fota>' \
    '</type>' \
    '</ota>' \
    '</manifest>' \
    '</items>' \
    '</otaUpdate>' \
    '</message>'

RESTART_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
    '<message>' \
    '    <restart id="389C0A">' \
    '        <items>' \
    '            <manifest>' \
    '                <type>cmd</type>' \
    '                <cmd>restart</cmd>' \
    '            </manifest>' \
    '        </items>' \
    '    </restart>' \
    '</message>'


SOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
                '<message>' \
                '	<otaUpdate id="389C0A">' \
                '		<items>' \
                '			<manifest>' \
                '				<type>ota</type>' \
                '				<ota>' \
                '					<header>' \
                '						<type>sota</type>' \
                '						<repo>local</repo>' \
                '					</header>' \
                '					<type>' \
                '						<sota>' \
                '							<cmd logtofile="y">update</cmd>' \
                '							<signature>123</signature>' \
                '							<path>/var/cache/manageability/test.mender</path>' \
                '							<release_date>2020-07-11</release_date>' \
                '						</sota>' \
                '					</type>' \
                '				</ota>' \
                '			</manifest>' \
                '		</items>' \
                '	</otaUpdate>' \
                '</message>'

POTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
                '<message>' \
                '    <otaUpdate id="389C0A">' \
                '        <items>' \
                '            <manifest>' \
                '                <type>ota</type>' \
                '                <ota>' \
                '                    <header>' \
                '                        <type>pota</type>' \
                '                        <repo>local</repo>' \
                '                    </header>' \
                '                    <type>' \
                '                        <pota>' \
                '                            <fota name="sample">' \
                '                                <path>/var/cache/manageability/fip.bin</path>' \
                '                                <biosversion>5.12</biosversion>' \
                '                                <vendor>American Megatrends Inc.</vendor>' \
                '                                <manufacturer>AAEON</manufacturer>' \
                '                                <product>Default string</product>' \
                '                                <releasedate>2022-02-08</releasedate>' \
                '                            </fota>' \
                '                            <sota>' \
                '                                <cmd logtofile="y">update</cmd>' \
                '                                <path>/var/cache/manageability/test.mender</path>' \
                '                                <release_date>2022-02-08</release_date>' \
                '                            </sota>' \
                '                       </pota>' \
                '                    </type>' \
                '                </ota>' \
                '            </manifest>' \
                '       </items>' \
                '    </otaUpdate>' \
                '</message>'

INVALID_OTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
    '<message>' \
    '<otaUpdate id="389C0A">' \
    '<items>' \
    '<manifest>' \
    '<type>ota</type>' \
    '<ota>' \
    '<header>' \
    '<type>fota</type>' \
    '<repo>local</repo>' \
    '</header>' \
    '<type>' \
    '</type>' \
    '</ota>' \
    '</manifest>' \
    '</items>' \
    '</otaUpdate>' \
    '</message>'

REVISED_FOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
    '            <manifest>' \
    '                <type>ota</type>' \
    '                <ota>' \
    '                    <header>' \
    '                        <type>fota</type>' \
    '                        <repo>local</repo>' \
    '                    </header>' \
    '                    <type>' \
    '                        <fota name="sample">' \
    '                            <path>/var/cache/manageability/X041_BIOS.tar</path>' \
    '                            <biosversion>5.12</biosversion>' \
    '                            <vendor>Dell Inc.</vendor>' \
    '                            <manufacturer>Dell Inc.</manufacturer>' \
    '                            <product>Aptio CRB</product>' \
    '                            <releasedate>2019-12-29</releasedate>' \
    '                        </fota>' \
    '                    </type>' \
    '                </ota>' \
    '            </manifest>'

REVISED_SOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
                        '            <manifest>' \
                        '                <type>ota</type>' \
                        '                <ota>' \
                        '                    <header>' \
                        '                        <type>sota</type>' \
                        '                        <repo>local</repo>' \
                        '                    </header>' \
                        '                    <type>' \
                        '                        <sota>' \
                        '                            <cmd logtofile="y">update</cmd>' \
                        '                            <signature>123</signature>' \
                        '                            <release_date>2020-07-11</release_date>' \
                        '                            <path>/var/cache/manageability/test.mender</path>' \
                        '                        </sota>' \
                        '                    </type>' \
                        '                </ota>' \
                        '            </manifest>'

REVISED_POTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?>' \
                        '            <manifest>' \
                        '                <type>ota</type>' \
                        '                <ota>' \
                        '                    <header>' \
                        '                        <type>pota</type>' \
                        '                        <repo>local</repo>' \
                        '                    </header>' \
                        '                    <type>' \
                        '                        <pota>' \
                        '                            <fota name="sample">' \
                        '                                <path>/var/cache/manageability/fip.bin</path>' \
                        '                                <biosversion>5.12</biosversion>' \
                        '                                <manufacturer>AAEON</manufacturer>' \
                        '                                <product>Default string</product>' \
                        '                                <vendor>American Megatrends Inc.</vendor>' \
                        '                                <releasedate>2022-02-08</releasedate>' \
                        '                            </fota>' \
                        '                            <sota>' \
                        '                                <cmd logtofile="y">update</cmd>' \
                        '                                <release_date>2022-02-08</release_date>' \
                        '                                <path>/var/cache/manageability/test.mender</path>' \
                        '                            </sota>' \
                        '                        </pota>' \
                        '                    </type>' \
                        '                </ota>' \
                        '            </manifest>'


class TestXLinkParser(TestCase):
    def setUp(self) -> None:
        self.parser = XLinkParser()

    def test_parse_RESTART(self):
        command_type, nid, dictionary, manifest, target_type = self.parser.parse(RESTART_MANIFEST)
        self.assertEqual(command_type, "restart")
        self.assertEqual(nid, "389C0A")
        self.assertEqual(dictionary, None)

    def test_parse_REQUEST_TO_DOWNLAOD_XML(self):
        command_type, sid, dictionary, manifest, target_type = self.parser.parse(
            REQUEST_TO_DOWNLOAD_XML)
        self.assertEqual(command_type, "requestToDownload")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, "765982")

    def test_parse_REGISTER_RESPONSE(self):
        command_type, sid, dictionary, manifest, target_type = self.parser.parse(
            REGISTER_RESPONSE_XML)
        self.assertEqual(command_type, "registerResponse")
        self.assertEqual(sid, "123ABC")
        self.assertEqual(dictionary, "20")

    def test_parse_IS_ALIVE_RESPONSE(self):
        command_type, sid, dictionary, manifest, target_type = self.parser.parse(
            REQUEST_IS_ALIVE_XML)
        self.assertEqual(command_type, "isAlive")
        self.assertEqual(sid, "123ABC")

    def test_parse_RESPONSE_fails(self):
        with self.assertRaises(XmlException):
            self.parser.parse(INVALID_XML)

    def test_parse_get_config_manifest(self):
        """Test _parse_config_manifest."""
        command_type, nid, dictionary, manifest, target_type = self.parser.parse(GET_ELEMENT_XML)
        self.assertRaises(XmlException)
        self.assertEqual(command_type, "getConfigValues")
        self.assertEqual(nid, "389C0A")
        self.assertEqual(dictionary, ['registrationRetryTimerSecs'])
        self.assertEqual(target_type, 'node')

    def test_parse_set_config_manifest(self):
        """Test _parse_config_manifest."""
        command_type, sid, dictionary, manifest, target_type = self.parser.parse(SET_ELEMENT_XML)
        self.assertRaises(XmlException)
        self.assertEqual(command_type, "setConfigValues")
        self.assertEqual(sid, "389C0A")
        self.assertEqual(dictionary, ['registrationRetryTimerSecs:30'])
        self.assertEqual(target_type, 'node')

    def test_load_config_manifest(self) -> None:
        """Test _load_config_manifest."""
        command_type, sid, dictionary, manifest, target_type = self.parser.parse(LOAD_XML)
        self.assertRaises(XmlException)
        self.assertEqual(command_type, "load")
        self.assertEqual(sid, "389C0A")
        self.assertEqual(dictionary, '/var/cache/manageability/intel_manageability_node.conf')

    @patch('node.xlink_parser.XLinkParser.check_command_type', return_value=(None, None))
    def test_raises_when_cmd_is_none(self, mock_check) -> None:
        with self.assertRaises(ValueError):
            self.parser.parse(GET_ELEMENT_XML)

    def test_check_command_type_raises_exception(self) -> None:
        self.assertRaises(NodeException, self.parser.check_command_type)

    def test_check_nid_raises_exception(self) -> None:
        self.assertRaises(NodeException, self.parser._check_nid)

    def test_parse_file_size_empty_handler_throw_exception(self) -> None:
        self.assertRaises(NodeException, self.parser._parse_file_size)

    def test_parse_file_size_empty_command_type_throw_exception(self) -> None:
        self.parser._xml_handler = Mock()
        self.parser.command_type = None
        self.assertRaises(NodeException, self.parser._parse_file_size)

    def test_parse_heartbeat_interval_empty_handler_throw_exception(self) -> None:
        self.assertRaises(NodeException, self.parser._parse_heartbeat_interval)

    def test_parse_config_manifest_empty_handler_throw_exception(self) -> None:
        self.assertRaises(NodeException, self.parser._parse_config_manifest)

    @patch("inbm_vision_lib.xml_handler.XmlHandler.get_multiple_children", return_value=({"test": "test"}, 1))
    def test_parse_config_manifest_throw_keyError_exception(self, append) -> None:
        self.assertRaises(NodeException, self.parser.parse, GET_ELEMENT_XML)

    def test_parse_fota_manifest_pass(self) -> None:
        self.assertEqual(REVISED_FOTA_MANIFEST, self.parser._parse_ota_manifest(FOTA_MANIFEST))

    def test_parse_sota_manifest_pass(self) -> None:
        self.assertEqual(REVISED_SOTA_MANIFEST, self.parser._parse_ota_manifest(SOTA_MANIFEST))

    def test_parse_pota_manifest_pass(self) -> None:
        self.assertEqual(REVISED_POTA_MANIFEST, self.parser._parse_ota_manifest(POTA_MANIFEST))

    @patch("inbm_vision_lib.xml_handler.XmlHandler.get_children", return_value=None)
    def test_parse_ota_manifest_throw_exception_empty_header(self, get_child) -> None:
        self.assertEqual(None, self.parser._parse_ota_manifest(FOTA_MANIFEST))

    def test_parse_config_request_manifest_empty_handler_throw_exception(self) -> None:
        self.assertRaises(NodeException, self.parser._parse_config_request_manifest)

    def test_parse_config_request_manifest_empty_command_type_throw_exception(self) -> None:
        self.parser._xml_handler = Mock()
        self.parser.command_type = None
        self.assertRaises(NodeException, self.parser._parse_config_request_manifest)

    def test_raises_when_nid_is_empty(self) -> None:
        with self.assertRaises(ValueError):
            self.parser.parse(MISSING_NID_XML)
