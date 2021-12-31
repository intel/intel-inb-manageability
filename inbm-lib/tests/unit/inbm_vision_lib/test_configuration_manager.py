import os
from unittest import TestCase
import xmlschema
from typing import Any, Dict
from mock import patch

from inbm_vision_lib.configuration_manager import ConfigurationManager, ConfigurationException


GOOD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
           '<configurations><node><registrationRetryTimerSecs>45</registrationRetryTimerSecs>' \
           '<registrationRetryLimit>60</registrationRetryLimit>' \
           '<XLinkPCIeDevID>1</XLinkPCIeDevID>' \
           '<heartbeatResponseTimerSecs>300</heartbeatResponseTimerSecs>' \
           '</node></configurations>'

BAD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
    '<configurations><node><registrationRetryTimerSecs>45</registrationRetryTimerSecs>' \
    '<registrationRetryLimit>time</registrationRetryLimit>' \
    '</node></configurations>'

# Use to test on local system.  Create directory structure and copy contents into files.
# SCHEMA_LOCATION = './fpm-template/usr/share/node-agent/intel_manageability_node_schema.xsd'
# NODE_CONF = './fpm-template/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'

SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'inbm-vision',
                               'node-agent', 'fpm-template', 'usr', 'share', 'node-agent', 'intel_manageability_node_schema.xsd')
NODE_CONF = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'inbm-vision',
                         'node-agent', 'fpm-template', 'etc', 'intel-manageability',
                         'public', 'node-agent', 'intel_manageability_node.conf')


class TestConfigurationManager(TestCase):

    def setUp(self) -> None:
        self.good = ConfigurationManager(GOOD_XML, is_file=False, schema_location=SCHEMA_LOCATION)
        self.good.get_root()

    def test_raises_when_schema_not_exist(self):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(GOOD_XML, is_file=False,
                                       schema_location='/no/existing/location')
            xml._validate_schema()

    @patch('os.path.islink', return_value=True)
    @patch('os.path.exists', return_value=True)
    def test_raises_when_schema_location_is_symlink(self, mock_exists, mock_islink):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(GOOD_XML, is_file=False,
                                       schema_location='/path')
            xml._validate_schema()

    def test_successfully_validate_good_xml_against_schema(self):
        try:
            good = ConfigurationManager(GOOD_XML, is_file=False, schema_location=SCHEMA_LOCATION)
            good._validate_schema()
        except xmlschema.XMLSchemaValidationError:
            self.fail("Raised exception when not expected.")

    def test_raises_on_bad_xml_against_schema(self):
        with self.assertRaises(ConfigurationException):
            ConfigurationManager(BAD_XML, is_file=False, schema_location=SCHEMA_LOCATION)

    def test_parse_good_xml_successfully(self):
        try:
            self.assertIsNotNone(self.good._root)
        except ConfigurationException:
            self.fail("Raised exception when not expected.")

    def test_validate_intel_manageability_conf(self):
        ConfigurationManager(NODE_CONF, schema_location=SCHEMA_LOCATION)

    def test_return_correct_values(self):
        self.assertEquals(['60', '45'],
                          self.good.get_element(['registrationRetryLimit', 'registrationRetryTimerSecs'], 'node'))

    def test_get_children_successfully(self):
        expected_children: Dict[str, Any] = {"registrationRetryTimerSecs": '45',
                                             "registrationRetryLimit": '60',
                                             "heartbeatResponseTimerSecs": '300',
                                             "XLinkPCIeDevID":  '1'}

        children = self.good.get_children('node')
        assert children is not None
        self.assertEquals(4, len(children))
        self.assertEquals(expected_children, children)

    def test_raise_when_path_not_found_getting_children(self):
        with self.assertRaises(ConfigurationException):
            self.good.get_children('nodes')

    def test_set_valid_values(self):
        self.assertEquals(['SUCCESS', 'SUCCESS', 'SUCCESS'],
                          self.good.set_element(['registrationRetryLimit:5', 'registrationRetryTimerSecs:11',
                                                 'XLinkPCIeDevID:1'], 'node'))

    def test_fail_on_bad_set_element(self):
        self.assertEquals(['Failed', 'Failed', 'Failed'],
                          self.good.set_element(['registrationRetryLimit:test', 'registrationRetryTimerSecs:test',
                                                 'XLinkPCIeDevID:test'], 'node'))

    @patch('os.remove')
    @patch('shutil.copyfile')
    @patch('shutil.copy')
    def test_load_successful(self, mock_copy, mock_copyfile, mock_remove):
        try:
            xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml.load(NODE_CONF)
        except ConfigurationException:
            self.fail("Raised exception when not expected.")

    @patch('os.remove')
    @patch('shutil.copyfile', side_effect=OSError)
    @patch('shutil.copy')
    def test_load_raises(self, mock_copy, mock_move, mock_remove):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml.load(NODE_CONF)

    @patch('os.remove')
    def test_load_raises_when_invalid_file_path(self, mock_remove):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml.load('/path/not/exist')

    @patch('os.remove')
    def test_load_raises_when_not_file(self, mock_remove):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(GOOD_XML, is_file=False, schema_location=SCHEMA_LOCATION)
            xml.load(NODE_CONF)

    def test_reload_xml(self):
        try:
            xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml.reload_xml()
        except ConfigurationException:
            self.fail("Raised exception when not expected.")

    @patch('os.remove')
    def test_raises_when_reload_xml_not_file(self, mock_remove):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager(GOOD_XML, is_file=False, schema_location=SCHEMA_LOCATION)
            xml.reload_xml()

    def test_validate_schema_of_file(self):
        try:
            xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml._validate_schema(NODE_CONF)
        except xmlschema.XMLSchemaValidationError:
            self.fail("Raised exception when not expected.")

    def test_get_element_in_file(self):
        xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        xml.get_root()
        self.assertEquals(['8', '20'],
                          xml.get_element(['registrationRetryLimit', 'registrationRetryTimerSecs'], 'node'))

    def test_raises_when_xml_file_not_exist(self):
        with self.assertRaises(ConfigurationException):
            xml = ConfigurationManager('/invalid/location', is_file=True,
                                       schema_location=SCHEMA_LOCATION)
            xml.get_root()

    def test_set_element_in_file(self):
        xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        xml.get_root()
        self.assertEquals(['SUCCESS', 'SUCCESS', 'SUCCESS'],
                          xml.set_element(['registrationRetryLimit:8', 'registrationRetryTimerSecs:10',
                                           'XLinkPCIeDevID:0'], 'node'))
        self.assertEquals(['8', '10', '0'],
                          xml.get_element(['registrationRetryLimit', 'registrationRetryTimerSecs',
                                           'XLinkPCIeDevID'], 'node'))

    def test_set_element_in_file_Failed(self):
        xml = ConfigurationManager(NODE_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        self.assertIsNotNone(xml)
        xml.get_root()
        self.assertEquals(['Failed', 'SUCCESS', 'SUCCESS'],
                          xml.set_element(['registrationRetryLimit:test', 'registrationRetryTimerSecs:20',
                                           'XLinkPCIeDevID:0'], 'node'))
        self.assertEquals(['8', '20', '0'],
                          xml.get_element(['registrationRetryLimit', 'registrationRetryTimerSecs',
                                           'XLinkPCIeDevID'], 'node'))
