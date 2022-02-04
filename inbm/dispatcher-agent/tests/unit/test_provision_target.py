import os
from unittest import TestCase
from mock import patch, Mock
from inbm_lib.xmlhandler import XmlHandler
from tarfile import TarInfo

from dispatcher.provision_target import _verify_files, ProvisionTarget
from dispatcher.dispatcher_exception import DispatcherException

TEST_XML = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
           '<fetch>https://www.repo.com/provision.tar</fetch><signature>signature</signature>' \
           '</provisionNode></manifest>'

TEST_XML_VALID_HASH_ALGO = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
    '<fetch>https://www.repo.com/provision.tar</fetch><signature>signature</signature>' \
    '<hash_algorithm>384</hash_algorithm></provisionNode></manifest>'

TEST_XML_INVALID_HASH_ALGO = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
    '<fetch>https://www.repo.com/provision.tar</fetch><signature>signature</signature>' \
    '<hash_algorithm>384abc</hash_algorithm></provisionNode></manifest>'

BAD_XML = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
    '<path>https://www.repo.com/provision.tar</path><signature>signature</signature>' \
    '</provisionNode></manifest>'

MODIFIED_XML = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
               '<blobPath>/var/cache/manageability/repository-tool/blob.bin</blobPath>' \
               '<certPath>/var/cache/manageability/repository-tool/test.crt</certPath></provisionNode></manifest>'

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')

blob_files = TarInfo(name="blob.bin")
cert_files = TarInfo(name="test.crt")
test_tar = Mock()


class TestProvisionTarget(TestCase):

    @patch('dispatcher.dispatcher_callbacks.DispatcherCallbacks')
    def setUp(self, mock_dispatcher):
        self.mocked_dispatcher = mock_dispatcher
        self.parsed = XmlHandler(xml=TEST_XML, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        self.parsed_hash_algo = XmlHandler(xml=TEST_XML_VALID_HASH_ALGO, is_file=False,
                                           schema_location=TEST_SCHEMA_LOCATION)

    def test_successfully_verify_files(self):
        files = [blob_files, cert_files]
        blob, cert = _verify_files(files)
        self.assertEqual(blob, 'blob.bin')
        self.assertEqual(cert, 'test.crt')

    def test_raises_when_cert_file_missing(self):
        files = [blob_files]
        with self.assertRaises(DispatcherException):
            _verify_files(files)

    def test_raises_when_blob_file_missing(self):
        files = [cert_files]
        with self.assertRaises(DispatcherException):
            _verify_files(files)

    def test_modifies_manifest(self):
        p = ProvisionTarget(TEST_XML, self.mocked_dispatcher, TEST_SCHEMA_LOCATION)
        self.assertEqual(MODIFIED_XML, p._modify_manifest('blob.bin', 'test.crt'))

    def test_raise_invalid_xml_file(self):
        p = ProvisionTarget(BAD_XML, self.mocked_dispatcher, TEST_SCHEMA_LOCATION)
        with self.assertRaises(DispatcherException):
            p._modify_manifest('blob.bin', 'test.crt')

    @patch('dispatcher.provision_target.extract_files_from_tar', return_value=([blob_files, cert_files], test_tar))
    @patch('dispatcher.provision_target.download')
    def test_successfully_install(self, mock_download, mock_extract):
        p = ProvisionTarget(TEST_XML, self.mocked_dispatcher, TEST_SCHEMA_LOCATION)
        p.install(self.parsed)

    @patch('dispatcher.provision_target.extract_files_from_tar', return_value=([blob_files, cert_files], test_tar))
    @patch('dispatcher.provision_target.download')
    def test_raise_on_install_with_invalid_hash_algorithm(self, mock_download, mock_extract):
        p = ProvisionTarget(TEST_XML_INVALID_HASH_ALGO,
                            self.mocked_dispatcher, TEST_SCHEMA_LOCATION)
        with self.assertRaises(DispatcherException):
            p.install(self.parsed_hash_algo)

    @patch('dispatcher.provision_target.extract_files_from_tar', return_value=(None, 'test.tar'))
    @patch('dispatcher.provision_target.download')
    def test_raise_not_enough_files_in_package(self, mock_download, mock_extract):
        p = ProvisionTarget(TEST_XML, self.mocked_dispatcher, TEST_SCHEMA_LOCATION)
        with self.assertRaises(DispatcherException):
            p.install(self.parsed)
