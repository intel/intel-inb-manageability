import mock
import os

from unittest import TestCase
from mock import Mock, patch
from unit.common.mock_resources import *
from dispatcher.common.result_constants import PUBLISH_SUCCESS
from dispatcher.ota_target import OtaTarget

from inbm_common_lib.constants import CONFIG_CHANNEL

TEST_XML = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><id>sampleID</id>' \
           '<type>fota</type><repo>remote</repo></header>' \
           '<type><fota name="sample"><targetType>host</targetType><fetch>https://abc.tar</fetch>' \
           '<biosversion>2018.03</biosversion><vendor>Intel</vendor><manufacturer>hisilicon</manufacturer>' \
           '<product>kmb-on-poplar</product><releasedate>2020-11-16</releasedate></fota></type></ota></manifest>'
TEST_POTA_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<manifest><type>ota</type><ota><header><type>pota</type><repo>remote</repo>' \
    '</header><type><pota><targetType>node</targetType>'\
    '<targets><target>node-id1</target><target>node-id2</target></targets>'\
    '<fota name="sample"><fetch>http://nat-ubuntu.jf.intel.com:8000/A1170000F60XE01.rar</fetch>' \
    '<biosversion>5.12</biosversion><sigversion>384</sigversion><signature>signature</signature>' \
    '<manufacturer>Default string</manufacturer><product>Default string</product>' \
    '<productversion>1</productversion><vendor>American Megatrends Inc.</vendor><releasedate>2018-02-08</releasedate>'\
    '<boot>boot</boot><guid>guid</guid><size>size</size><tooloptions>/p /b</tooloptions>'\
    '<username>user1</username><password>pwd</password></fota>' \
    ' <sota><cmd logtofile="y">update</cmd><fetch>http://nat-ubuntu.jf.intel.com:8000/file.mender</fetch>' \
    '<signature>signature</signature><username>user</username><password>pwd</password>'\
    '<release_date>2020-10-10</release_date></sota>  '\
    '</pota></type></ota></manifest>'
MODIFIED_TEST_XML = '<manifest><type>ota</type><ota><header>' \
                    '<id>sampleID</id><type>fota</type><repo>local</repo>' \
                    '</header><type><fota name="sample"><targetType>host</targetType>' \
                    '<biosversion>2018.03</biosversion><vendor>Intel</vendor><manufacturer>hisilicon</manufacturer>' \
                    '<product>kmb-on-poplar</product><releasedate>2020-11-16</releasedate>' \
                    '<path>/var/cache/manageability/repository-tool/abc.tar</path></fota></type></ota></manifest>'
TEST_XML_WITH_CREDENTIALS = '<?xml version="1.0" encoding="utf-8"?>' \
    '<manifest><type>ota</type><ota><header><id>sampleID</id>' \
    '<type>fota</type><repo>remote</repo></header><type><fota name="sample">' \
    '<targetType>host</targetType><fetch>https://abc.tar</fetch><biosversion>2018.03</biosversion>' \
    '<username>user</username><password>mypassword</password>' \
    '<vendor>Intel</vendor><manufacturer>hisilicon</manufacturer><product>kmb-on-poplar</product><releasedate>' \
    '2020-11-16</releasedate></fota></type></ota></manifest>'
TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')
ota_element = {'fetch': 'https://abc.tar'}
parsed_manifest = {'uri': 'https://abc.com', 'signature': 'asdf',
                   'hash_algorithm': '3',
                   'resource': ota_element,
                   'username': 'uname',
                   'password': 'pwd'}
pota_parsed_manifest = {'ota_type': 'pota', 'fota': {'uri': 'http://nat-ubuntu.jf.intel.com:8000/A1170000F60XE01.rar', 'signature': 'signature', 'hash_algorithm': 384, 'resource': {'fetch': 'http://nat-ubuntu.jf.intel.com:8000/A1170000F60XE01.rar', 'biosversion': '5.12', 'sigversion': '384', 'signature': 'signature', 'manufacturer': 'Default string', 'product': 'Default string', 'productversion': '1', 'vendor': 'American Megatrends Inc.', 'releasedate': '2018-02-08', 'boot': 'boot', 'guid': 'guid', 'size': 'size', 'tooloptions': '/p /b', 'username': 'user1',
                                                                                                                                                                                     'password': 'pwd', 'targetType': 'node', 'targets': '                '}, 'username': 'user1', 'password': 'pwd'}, 'sota': {'sota_cmd': 'update', 'log_to_file': 'y', 'uri': 'http://nat-ubuntu.jf.intel.com:8000/file.mender', 'signature': 'signature', 'hash_algorithm': 384, 'resource': {'cmd': 'update', 'fetch': 'http://nat-ubuntu.jf.intel.com:8000/file.mender', 'signature': 'signature', 'username': 'user', 'password': 'pwd', 'release_date': '2020-10-10', 'targetType': 'node', 'targets': '                '}, 'username': 'user', 'password': 'pwd', 'release_date': '2020-10-10'}}


class TestPublishTargetOta(TestCase):

    @mock.patch('dispatcher.dispatcher_callbacks.DispatcherBroker', autospec=True)
    def setUp(self, mock_broker):
        self.mocked_broker = mock_broker.return_value

    @patch('dispatcher.ota_target.download')
    @patch('dispatcher.ota_target.OtaTarget._modify_manifest')
    def test_ota_target(self, mock_modify, mock_download) -> None:
        mock_callback = Mock()
        t = OtaTarget(TEST_XML, parsed_manifest, "FOTA", mock_callback)
        status = t.install()
        mock_modify.assert_called_once()
        mock_download.assert_called_once()
        self.assertEquals(status, PUBLISH_SUCCESS)

    @patch('inbm_lib.xmlhandler.XmlHandler.__init__')
    @patch('inbm_lib.xmlhandler.XmlHandler.add_attribute')
    @patch('inbm_lib.xmlhandler.XmlHandler.set_attribute')
    @patch('inbm_lib.xmlhandler.XmlHandler.remove_attribute')
    @patch('dispatcher.ota_target.download')
    @patch('dispatcher.dispatcher_callbacks.DispatcherCallbacks')
    def test_publish_fota(self, mock_callback, mock_download, mock_rmv, mock_set, mock_add, mock_xmlhandler) -> None:
        mock_callback = Mock()
        mock_xmlhandler.return_value = None
        t = OtaTarget(TEST_XML, parsed_manifest, "FOTA", mock_callback)
        t.install()
        mock_download.assert_called_once()

    @patch('inbm_lib.xmlhandler.XmlHandler.__init__')
    @patch('inbm_lib.xmlhandler.XmlHandler.add_attribute')
    @patch('inbm_lib.xmlhandler.XmlHandler.set_attribute')
    @patch('inbm_lib.xmlhandler.XmlHandler.remove_attribute')
    @patch('dispatcher.ota_target.download')
    @patch('dispatcher.dispatcher_callbacks.DispatcherCallbacks')
    @patch('dispatcher.ota_target.OtaTarget._modify_manifest')
    def test_publish_pota(self, mock_modify_manifest, mock_callback, mock_download, mock_rmv, mock_set, mock_add, mock_xmlhandler) -> None:
        mock_callback = Mock()
        mock_xmlhandler.return_value = None
        t = OtaTarget(TEST_POTA_XML, pota_parsed_manifest, "POTA", mock_callback)
        t.install()
        mock_download.assert_called()
        self.assertEqual(mock_download.call_count, 2)
        mock_modify_manifest.assert_called_once()

    def test_modify_manifest_without_credential_info(self):
        mock_callback = Mock()
        t = OtaTarget(TEST_XML, parsed_manifest, "FOTA", mock_callback)
        m = t._modify_manifest(schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(m, MODIFIED_TEST_XML)

    def test_modify_manifest_with_credential_info(self):
        mock_callback = Mock()
        t = OtaTarget(TEST_XML_WITH_CREDENTIALS, parsed_manifest, "FOTA", mock_callback)
        m = t._modify_manifest(schema_location=TEST_SCHEMA_LOCATION)
        self.assertEqual(m, MODIFIED_TEST_XML)
