import os

from unittest import TestCase
from mock import patch

from inbm_vision_lib.xml_handler import XmlException, XmlHandler

from vision.manifest_parser import parse_manifest, _parse_config_request, TargetParsedManifest
from vision.constant import VisionException


TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/vision-agent/'
                                    'manifest_schema.xsd')

GOOD_FOTA_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>ota</type>     ' \
                '<ota><header><type>fota</type><repo>local</repo></header>' \
                '<type><fota name="sample"><targetType>node</targetType><targets><target>123ABC</target></targets>' \
                '<signature>123</signature><biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor>' \
                '<manufacturer>Default string</manufacturer><product>Default string</product><releasedate>2018-03-30' \
                '</releasedate><path>/var/cache/manageability/X041_BIOS.tar</path></fota></type></ota> </manifest>'

GOOD_FOTA_XML_WO_TARGETS = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>ota</type>     ' \
                           '<ota><header><type>fota</type><repo>local</repo></header>' \
                           '<type><fota name="sample"><targetType>node</targetType>' \
                           '<signature>123</signature><biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor>' \
                           '<manufacturer>Default string</manufacturer><product>Default string</product><releasedate>2018-03-30' \
                           '</releasedate><path>/var/cache/manageability/X041_BIOS.tar</path></fota></type></ota> </manifest>'

GOOD_SOTA_XML = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type>' \
                '<repo>local</repo></header><type><sota><cmd logtofile="y">update</cmd><targetType>node</targetType>' \
                '<targets><target>389C0A</target></targets><signature>123</signature><username>test_user</username>' \
                '<password>test_password</password><release_date>2020-07-11</release_date>' \
                '<path>/var/cache/manageability/repository-tool/test.mender</path></sota></type></ota></manifest>'

GOOD_POTA_XML = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>pota</type>' \
                '<repo>local</repo></header><type><pota><targetType>node</targetType><targets><target>389C0A</target>' \
                '</targets><fota name="sample"><signature>fota_signature</signature><biosversion>5.12</biosversion>' \
                '<manufacturer>Dell Inc.</manufacturer><product>Default string</product><vendor>Dell Inc.</vendor>' \
                '<releasedate>2022-02-08</releasedate><path>/var/cache/repository_tool/fip.tar</path></fota><sota>' \
                '<cmd logtofile="y">update</cmd><signature>sota_signature</signature><release_date>2022-02-09' \
                '</release_date><path>/var/cache/repository_tool/test.mender</path></sota></pota></type>' \
                '</ota></manifest>'

QUERY_NODE_ALL_XML = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query>' \
                     '<option>all</option><targetType>node</targetType></query></manifest>'

RESTART_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd><restart>' \
                   '<targetType>node</targetType><targets><target>389C0A</target><target>123ABC</target>' \
                   '</targets></restart></manifest>'

VISION_REMOVE_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>config</type>  ' \
                                '<config><cmd>remove</cmd><targetType>vision</targetType>' \
                                '<configtype><remove><path>trustedRepositories</path>' \
                                '</remove></configtype></config></manifest>'


VISION_GET_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>config</type>     ' \
                             '<config>         <cmd>get_element</cmd>         <targetType>vision</targetType>' \
                             '         <configtype>             <get>                 ' \
                             '<path>isAliveTimerSecs;heartbeatRetryLimit</path>             ' \
                             '</get>         </configtype>     </config> </manifest>'

VISION_SET_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>config</type>  ' \
                             '   <config>         <cmd>set_element</cmd>         <targetType>vision</targetType>' \
                             '         <configtype>             <set>                 ' \
                             '<path>heartbeatCheckIntervalSecs:20;heartbeatRetryLimit:20</path>' \
                             '             </set>         </configtype>     </config> </manifest>'

VISION_APPEND_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>config</type>  ' \
                                '<config><cmd>append</cmd><targetType>vision</targetType>' \
                                '<configtype><append><path>trustedRepositories:https://dummyURL.com</path>' \
                                '</append></configtype></config></manifest>'

NODE_CLIENT_APPEND_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>config</type>  ' \
                                     '<config><cmd>append</cmd><targetType>node_client</targetType>' \
                                     '<configtype><targets><target>389C0A</target><target>123ABC</target>' \
                                     '</targets><append><path>trustedRepositories:https://dummyURL.com</path>' \
                                     '</append></configtype></config></manifest>'

NODE_CLIENT_REMOVE_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>config</type>  ' \
                                     '<config><cmd>remove</cmd><targetType>node_client</targetType><configtype>' \
                                     '<remove><path>trustedRepositories</path></remove></configtype></config></manifest>'

PARSED_FOTA_VALUE = {'repo': 'local', 'ota': 'fota', 'path': '/var/cache/manageability/X041_BIOS.tar',
                     'biosversion': '5.12', 'vendor': 'American Megatrends Inc.', 'manufacturer': 'Default string',
                     'product': 'Default string', 'releasedate': '2018-03-30', 'signature': '123', 'node_id0': '123ABC'}

PARSED_FOTA_VALUE_WO_TARGET = {'repo': 'local', 'ota': 'fota', 'path': '/var/cache/manageability/X041_BIOS.tar',
                               'biosversion': '5.12', 'vendor': 'American Megatrends Inc.',
                               'manufacturer': 'Default string',
                               'product': 'Default string', 'releasedate': '2018-03-30', 'signature': '123'}

PARSED_SOTA_VALUE = {'repo': 'local', 'ota': 'sota', 'path': '/var/cache/manageability/repository-tool/test.mender',
                     'release_date': '2020-07-11', 'cmd': 'update', 'signature': '123', 'logtofile': 'y',
                     'node_id0': '389C0A'}

PARSED_POTA_VALUE = {'repo': 'local', 'ota': 'pota', 'biosversion': '5.12', 'vendor': 'Dell Inc.',
                     'manufacturer': 'Dell Inc.',
                     'product': 'Default string', 'releasedate': '2022-02-08', 'fota_signature': 'fota_signature',
                     'fota_path': '/var/cache/repository_tool/fip.tar', 'release_date': '2022-02-09', 'cmd': 'update',
                     'logtofile': 'y', 'sota_path': '/var/cache/repository_tool/test.mender', 'node_id0': '389C0A',
                     'sota_signature': 'sota_signature'}

VISION_LOAD_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>config</type><config>' \
                              '<cmd>load</cmd><targetType>vision</targetType><configtype><load>' \
                              '<path>/var/cache/manageability/vision.conf</path></load></configtype>' \
                              '</config></manifest>'

NODE_REMOVE_CONFIG_MANIFEST = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>config</type>  ' \
                              '<config><cmd>remove</cmd><targetType>node</targetType>' \
                              '<configtype><remove><path>trustedRepositories</path>' \
                              '</remove></configtype></config></manifest>'

BAD_VISION_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest>     <type>ota</type>     ' \
                 '<ota>         <header>' \
                 '         <type></type>             <repo>remote</repo>     ' \
                 '    </header>         <type>             <fota name="sample">     ' \
                 '            <targets>                     <target>slave-id1</target>     ' \
                 '                <target>slave-id2</target>                     ' \
                 '<target>vision-id</target>     ' \
                 '            </targets>                ' \
                 ' <fetch>http://10.108.50.83/test_files/bmpv2/test-files-1068/mutate-fail-1.0-1' \
                 '.noarch.tar</fetch> ' \
                 '                <biosversion>1.0</biosversion>   ' \
                 '              <vendor>American Megatrends Inc.</vendor>  ' \
                 '               <manufacturer>Default string</manufacturer>   ' \
                 '              <product>Default string</product>            ' \
                 '     <releasedate>2018-03-30</releasedate>              ' \
                 '   <path>/var/cache/repository-tool</path>       ' \
                 '      </fota>         </type>     </ota> </manifest>'


class TestManifestParser(TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    def test_parser_FOTA_success(self):
        parsed_manifest = parse_manifest(
            GOOD_FOTA_XML, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(parsed_manifest.manifest_type, "fota")
        self.assertEqual(parsed_manifest.info, PARSED_FOTA_VALUE)
        self.assertEqual(parsed_manifest.targets, ["123ABC"])

    def test_parser_FOTA_success_wo_targets(self):
        parsed_manifest = parse_manifest(
            GOOD_FOTA_XML_WO_TARGETS, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(parsed_manifest.manifest_type, "fota")
        self.assertEqual(parsed_manifest.info, PARSED_FOTA_VALUE_WO_TARGET)
        self.assertEqual(parsed_manifest.targets, [])

    def test_parser_SOTA_success(self):
        parsed_manifest = parse_manifest(
            GOOD_SOTA_XML, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(parsed_manifest.manifest_type, "sota")
        self.assertEqual(parsed_manifest.info, PARSED_SOTA_VALUE)
        self.assertEqual(parsed_manifest.targets, ["389C0A"])

    def test_parser_POTA_success(self):
        parsed_manifest = parse_manifest(
            GOOD_POTA_XML, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(parsed_manifest.manifest_type, "pota")
        self.assertEqual(parsed_manifest.info, PARSED_POTA_VALUE)
        self.assertEqual(parsed_manifest.targets, ["389C0A"])

    def test_parser_fail(self):
        self.assertRaises(XmlException, parse_manifest, BAD_VISION_XML)

    @patch('inbm_vision_lib.xml_handler.XmlHandler.get_element', return_value="unknown")
    def test_parse_invalid_request(self, get_element):
        self.assertRaises(VisionException, parse_manifest,
                          GOOD_FOTA_XML, TEST_SCHEMA_LOCATION)
        get_element.assert_called_once()

    def test_parse_restart_request(self) -> None:
        parsed_manifest = parse_manifest(
            RESTART_MANIFEST, schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(parsed_manifest.manifest_type, "restart")
        self.assertEqual(parsed_manifest.info, {})
        self.assertEqual(parsed_manifest.targets, ['389C0A', '123ABC'])

    def test_parse_vision_get_config_request(self) -> None:
        parsed_manifest = parse_manifest(
            VISION_GET_CONFIG_MANIFEST,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "get_element")
        self.assertEqual(tpm.info['path'], "isAliveTimerSecs;heartbeatRetryLimit")
        self.assertEqual(tpm.targets, [])
        self.assertEqual(tpm.target_type, "vision")

    def test_parse_vision_set_config_request(self) -> None:
        parsed_manifest = parse_manifest(
            VISION_SET_CONFIG_MANIFEST,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "set_element")
        self.assertEqual(tpm.info['path'], "heartbeatCheckIntervalSecs:20;heartbeatRetryLimit:20")
        self.assertEqual(tpm.targets, [])
        self.assertEqual(tpm.target_type, "vision")

    def test_parse_node_client_append_config_request(self):
        parsed_manifest = parse_manifest(
            NODE_CLIENT_APPEND_CONFIG_MANIFEST,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "append")
        self.assertEqual(tpm.info['path'], "trustedRepositories:https://dummyURL.com")
        self.assertEqual(tpm.targets, ['389C0A', '123ABC'])
        self.assertEqual(tpm.target_type, "node_client")

    def test_vision_non_node_client_append_config_request(self):
        with self.assertRaises(VisionException):
            parse_manifest(VISION_APPEND_CONFIG_MANIFEST, schema_location=TEST_SCHEMA_LOCATION)

    def test_parse_node_client_remove_config_request(self):
        parsed_manifest = parse_manifest(
            NODE_CLIENT_REMOVE_CONFIG_MANIFEST,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "remove")
        self.assertEqual(tpm.info['path'], "trustedRepositories")
        self.assertEqual(tpm.target_type, "node_client")

    def test_vision_non_node_client_remove_config_request(self):
        with self.assertRaises(VisionException):
            parse_manifest(VISION_REMOVE_CONFIG_MANIFEST, schema_location=TEST_SCHEMA_LOCATION)

    def test_parse_load_config_request(self):
        parsed_manifest = parse_manifest(
            VISION_LOAD_CONFIG_MANIFEST,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "load")
        self.assertEqual(tpm.info['path'], "/var/cache/manageability/vision.conf")
        self.assertEqual(tpm.targets, [])
        self.assertEqual(tpm.target_type, "vision")

    def test_parse_node_remove_config_request(self):
        self.assertRaises(VisionException, _parse_config_request,
                          XmlHandler(NODE_REMOVE_CONFIG_MANIFEST))

    def test_parse_query_node_request(self):
        parsed_manifest = parse_manifest(
            QUERY_NODE_ALL_XML,
            schema_location=TEST_SCHEMA_LOCATION)
        tpm = TargetParsedManifest.from_instance(parsed_manifest)

        self.assertEqual(tpm.manifest_type, "query")
        self.assertEqual(tpm.info['option'], "all")
        self.assertEqual(tpm.targets, [])
        self.assertEqual(tpm.target_type, "node")
