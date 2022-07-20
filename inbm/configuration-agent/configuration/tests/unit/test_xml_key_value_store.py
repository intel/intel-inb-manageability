import os
import unittest
from unittest import TestCase
from unittest.mock import mock_open
from xml.etree.ElementTree import ElementTree

from configuration.xml_key_value_store import XmlException, XmlKeyValueStore
from configuration.configuration_exception import ConfigurationException
from mock import patch
from typing import Any

SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                               '..', '..', '..', 'fpm-template', 'usr', 'share',
                               'configuration-agent', 'iotg_inb_schema.xsd')

INVALID_SCHEMA_FILE_LOCATION = '/etc/intel-manageability/intel_manageability.conf'

IOTG_INB_CONF = os.path.join(os.path.dirname(__file__),
                             '..', '..', '..', 'fpm-template', 'etc', 'intel_manageability.conf')

GOOD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
           '<configurations><all><dbs>ON</dbs></all>' \
           '<telemetry><collectionIntervalSeconds>60</collectionIntervalSeconds>' \
           '<publishIntervalSeconds>300</publishIntervalSeconds><maxCacheSize>100</maxCacheSize>' \
           '<containerHealthIntervalSeconds>600</containerHealthIntervalSeconds>' \
           '</telemetry><diagnostic><minStorageMB>100</minStorageMB><minMemoryMB>200</minMemoryMB>' \
           '<minPowerPercent>20</minPowerPercent><sotaSW>docker' \
           '</sotaSW></diagnostic><dispatcher><dbsRemoveImageOnFailedContainer>true</dbsRemoveImageOnFailedContainer>' \
           '<trustedRepositories>https://sample</trustedRepositories>' \
           '</dispatcher><orchestrator name="csl-agent"><orchestratorResponse>true</orchestratorResponse>' \
           '<ip>/etc/ip</ip><token>/etc/token</token><certFile>/etc/pem</certFile></orchestrator><sota>' \
           '<ubuntuAptSource>https://sample2</ubuntuAptSource>' \
           '<proceedWithoutRollback>false</proceedWithoutRollback></sota></configurations>'

BAD_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
          '<configurations><all><dbs>ON</dbs></all>' \
          '<telemetry><collectionIntervalSeconds>60</collectionIntervalSeconds>' \
          '<publishIntervalSeconds>300</publishIntervalSeconds><maxCacheSize>100</maxCacheSize>' \
          '<containerHealthIntervalSeconds>600</containerHealthIntervalSeconds>' \
          '</telemetry><diagnostic><minStorageMB>100</minStorageMB><minMemoryMB>200</minMemoryMB>' \
          '<minPowerPercent>20<sotaSW>docker' \
          '</sotaSW></diagnostic><dispatcher><dbsRemoveImageOnFailedContainer>' \
          'true</dbsRemoveImageOnFailedContainer>' \
          '<trustedRepositories>https://sample</trustedRepositories></dispatcher>' \
          '<sota><ubuntuAptSource>https://sample2</ubuntuAptSource>' \
          '<proceedWithoutRollback>false</proceedWithoutRollback></sota></configurations>'

INVALID_XML = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<configurations><all><dbs>ON</dbs></all>' \
              '<telemetry><collectionIntervalSeconds>60</collectionIntervalSeconds>' \
              '<publishIntervalSeconds>300</publishIntervalSeconds><maxCacheSize>100</maxCacheSize>' \
              '<containerHealthIntervalSeconds>600</containerHealthIntervalSeconds>' \
              '</telemetry><diagnostic><minStorageMB>100</minStorageMB><minMemoryMB>200</minMemoryMB>' \
              '<minPowerPercent>20</minPowerPercent><sotaSW>docker' \
              '</sotaSW></diagnostic><dispatcher><trustedRepositories>' \
              'https://sample</trustedRepositories></dispatcher>' \
              '<sota><ubuntuAptSource>https://sample2</ubuntuAptSource>' \
              '<proceedWithoutRollback>false</proceedWithoutRollbacks></sota></configurations>'


class TestXmlParser(TestCase):

    def setUp(self):
        self.good = XmlKeyValueStore(GOOD_XML, is_file=False, schema_location=SCHEMA_LOCATION)

    def test_parser_creation_success(self):
        self.assertIsNotNone(self.good)

    def test_parser_creation_xml_none_success(self):
        self.assertIsNotNone(XmlKeyValueStore)

    def test_parser_creation_failure(self):
        self.assertRaises(XmlException, XmlKeyValueStore, BAD_XML,
                          is_file=False, schema_location=SCHEMA_LOCATION)

    def test_xsd_validation_failure(self):
        self.assertRaises(XmlException, XmlKeyValueStore, INVALID_XML,
                          is_file=False, schema_location=SCHEMA_LOCATION)

    def test_invalid_schema_file_path_failure(self):
        self.assertRaises(XmlException, XmlKeyValueStore, INVALID_SCHEMA_FILE_LOCATION,
                          is_file=True, schema_location=SCHEMA_LOCATION)

    def test_validate_intel_manageability_conf(self):
        XmlKeyValueStore(IOTG_INB_CONF, True, schema_location=SCHEMA_LOCATION)

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._validate')
    @patch('builtins.open', new_callable=mock_open())
    @patch('os.remove')
    def test_load_raises_move_fails(self, mock_remove, mock_open_file, mock_validate):
        mock_validate.return_value = ElementTree()
        mock_open_file.side_effect = IOError('abc')
        with self.assertRaises(XmlException):
            XmlKeyValueStore(IOTG_INB_CONF, is_file=False, schema_location=SCHEMA_LOCATION) \
                .load('/opt/intel_manageability.conf')

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._validate')
    @patch('shutil.copy')
    @patch('shutil.move')
    def test_load_raises_copy_fails(self, mock_move, mock_copy, mock_validate):
        mock_validate.return_value = ElementTree()
        mock_copy.side_effect = OSError('abc')
        with self.assertRaises(XmlException):
            XmlKeyValueStore(IOTG_INB_CONF, is_file=False, schema_location=SCHEMA_LOCATION) \
                .load('/opt/intel_manageability.conf')

    def test_get_element(self):
        self.assertEquals('telemetry/maxCacheSize:100',
                          self.good.get_element('telemetry/maxCacheSize'))

    def test_get_element_throws_exception(self):
        self.assertRaises(XmlException, self.good.get_element, 'telemetry/maxCacheSize/bb')

    def test_set_element(self):
        self.assertEquals('telemetry/maxCacheSize:100',
                          self.good.get_element(path='telemetry/maxCacheSize'))
        self.good.set_element('telemetry/maxCacheSize', '200')
        self.assertEquals('telemetry/maxCacheSize:200',
                          self.good.get_element('telemetry/maxCacheSize'))

    def test_validate_file(self):
        try:
            XmlKeyValueStore(IOTG_INB_CONF, is_file=False, schema_location="/path")
        except XmlException as e:
            self.assertEqual("Schema file not found.", str(e))

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    def test_set_element_in_file(self, mock_write):
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        path = xml.set_element('telemetry/maxCacheSize', '200')
        self.assertEquals('200', path)
        mock_write.assert_called_once()

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    def test_set_element_in_file_fail_write(self, mock_write):
        try:
            mock_write.side_effect = XmlException('error')
            xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            path = xml.set_element('telemetry/maxCacheSize', 'a')
            self.assertEquals('a', path)
            mock_write.assert_called_once()
        except ConfigurationException as e:
            self.assertEquals('Exception caught while writing to file', str(e))

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    @patch('configuration.xml_key_value_store.XmlKeyValueStore._validate_file')
    def test_set_element_in_file_write_raise_exception(self, mock_validate: Any, mock_write: Any) -> None:
        try:
            mock_write.side_effect = ConfigurationException('error')
            xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            path = xml.set_element('telemetry/maxCacheSize', '127')
            self.assertEquals('127', path)
        except ConfigurationException as e:
            self.assertEquals('error', str(e))

    def test_get_children(self) -> None:
        empty = {'minMemoryMB': '200', 'minPowerPercent': '20',
                 'minStorageMB': '100', 'sotaSW': 'docker'}
        children_list = self.good.get_children('diagnostic')
        self.assertEquals(children_list, empty)

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    @patch('configuration.xml_key_value_store.XmlKeyValueStore._validate_file')
    def test_set_element_in_file_fail_validate(self, mock_validate, mock_write):
        mock_validate.return_value = False
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        path = xml.set_element('telemetry/maxCacheSize', 'a')
        self.assertEquals('a', path)
        self.assertEquals(mock_write.call_count, 1)
        mock_validate.assert_called_once()

    def test_set_element_throws_exception(self):
        self.assertRaises(XmlException, self.good.set_element, 'telemetry/maxCacheSize/bb', '200')

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    def test_append_element_in_file(self, mock_write):
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        path = xml.append('dispatcher', value_string='trustedRepositories:https://dummy')
        self.assertRegex(path, "dummy")
        mock_write.assert_called_once()

    @patch('configuration.xml_key_value_store.XmlKeyValueStore.get_element',
           return_value="dispatcher/trustedRepositories: http\n\t  https")
    @patch('configuration.xml_key_value_store.XmlKeyValueStore._write_to_file')
    def test_remove_element_in_file(self, mock_write, mock_get_ele_val):
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        path = xml.remove('dispatcher', value_string='trustedRepositories:https')
        self.assertEquals('dispatcher/trustedRepositories:\n\t    http\n\t;', path)
        mock_write.assert_called_once()

    def test_get_parent_success(self) -> None:
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        self.assertEquals('telemetry', xml.get_parent('maxCacheSize'))

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._update_file')
    def test_set_element_attribute_value_fail(self, mock_update_file) -> None:
        try:
            xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml._set_element_attribute_value('orchestration', 'service')
            mock_update_file.assert_not_called()
        except XmlException as e:
            self.assertEqual('Cannot find element at specified path: orchestration', str(e))

    @patch('configuration.xml_key_value_store.XmlKeyValueStore._update_file')
    def test_set_element_attribute_value_pass(self, mock_update_file) -> None:
        xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
        xml._set_element_attribute_value('orchestrator', 'service')
        mock_update_file.assert_called_once()

    def test_get_parent_failure(self) -> None:
        try:
            xml = XmlKeyValueStore(IOTG_INB_CONF, is_file=True, schema_location=SCHEMA_LOCATION)
            xml.get_parent('size')
        except XmlException as e:
            self.assertNotEqual(XmlException(
                'Cannot find the parent for specified child tag: size'), str(e))
