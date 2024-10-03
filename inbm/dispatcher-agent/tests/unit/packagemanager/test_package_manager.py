import hashlib
import unittest
from binascii import hexlify
from unittest import TestCase

from ..common.mock_resources import MockDispatcherBroker
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest.mock import patch, mock_open, MagicMock
from tarfile import TarFile

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager import package_manager
from dispatcher.packagemanager.memory_repo import MemoryRepo
from dispatcher.packagemanager.package_manager import extract_files_from_tar, DispatcherBroker, \
    _get_checksum, get_file_type, verify_signature, verify_source, _get_ext, \
    _is_valid_file, _verify_checksum_with_key, _is_source_match_trusted_repo, _parse_config_result
from dispatcher.common.result_constants import Result
from tarfile import TarFile
from base64 import b64encode, b64decode

import requests_mock

from inbm_common_lib.utility import canonicalize_uri


class MockTrtl:

    def __init__(self, smart_error=False, ver_err=False) -> None:
        self.getlatesttag_called = False
        self.error = smart_error
        self.ver_err = ver_err

    def execute(self, image, version, command):
        if 'smart info' in command and not self.error and not self.ver_err:
            return 'blah\nVersion: 1.0@noarch\nblah', '', 0
        elif self.ver_err:
            return '', '', 1
        elif not self.error:
            return '', '', 0
        else:
            return '', 'Error received', 1

    def get_latest_tag(self, image):
        self.getlatesttag_called = True
        return 1, 0


class MockFile:

    def __init__(self, name) -> None:
        self.name = name


class MockTar(TarFile):
    def __init__(self, name) -> None:
        self.name = name

    def close(self) -> None:
        pass


class MockResponse:

    def __init__(self, resp_data, code=200, msg='OK') -> None:
        self.resp_data = resp_data
        self.code = code
        self.msg = msg
        self.headers = {'content-type': 'text/plain; charset=utf-8'}

    def read(self):
        return self.resp_data

    def get_code(self):
        return self.code


class TestManager(TestCase):

    def __check_str_type(self, usrname, pswd):
        string_to_encode = '%s:%s' % (usrname, pswd)
        base64string = b64encode(str(string_to_encode).encode('utf-8'))
        return string_to_encode, base64string

    def test_trtl_usr_pwd_encoding_bytes(self) -> None:
        given_str, b64_str = self.__check_str_type("usrnameString", "passwordString")
        decode_str = b64decode(b64_str).decode('utf-8', errors='strict')
        assert type(b64decode(b64_str)) is bytes
        self.assertEqual(given_str, decode_str)

    def test_check_invalid_file(self) -> None:
        result, _ = extract_files_from_tar(
            '/proc/cpuinfo')
        self.assertIsNone(result)

    def test_get_file_type_success(self) -> None:
        result = get_file_type('abc.rpm')
        self.assertEqual(result, 'package')

        result = get_file_type('rpm.deb')
        self.assertEqual(result, 'package')

    def test_get_file_type_fail(self) -> None:
        result = get_file_type('abc.abc')
        self.assertEqual(result, None)

    def test_verify_source_empty_source_fail(self) -> None:
        with self.assertRaisesRegex(DispatcherException, 'Source verification failed.  Download aborted.'):
            verify_source(None,
                          MockDispatcherBroker.build_mock_dispatcher_broker())

    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    def test_verify_signature_invalid_tar_fail(self, mockup) -> None:
        mockup.return_value = None, None
        with self.assertRaisesRegex(DispatcherException, "Signature check failed. Unsupported file format."):
            verify_signature(
                "signature", "path", MockDispatcherBroker.build_mock_dispatcher_broker(), 384)

    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    @patch("dispatcher.packagemanager.package_manager._is_valid_file")
    @patch("dispatcher.configuration_helper.open")
    def test_load_file_content_for_checksum_fail(self, mock_open, mock_valid_file, mockup) -> None:
        mockup.return_value = 'files', MockTar('tar')
        mock_open.side_effect = OSError('abc')
        mock_valid_file.return_value = True
        with self.assertRaises(DispatcherException):
            verify_signature(
                "signature", "path/to/file.tar", MockDispatcherBroker.build_mock_dispatcher_broker(), 384)

    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    def test_file_content_empty_tar_fail(self, mockup) -> None:
        mockup.return_value = None, MockTar('tar')
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Invalid tar ball. '
                                                         'No package found in tarball while validating signature.'):
            verify_signature(
                "signature", "path/to/file.tar", MockDispatcherBroker.build_mock_dispatcher_broker(), 384)

    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    @patch("dispatcher.packagemanager.package_manager._is_valid_file")
    @patch("builtins.open")
    @patch("dispatcher.packagemanager.package_manager._get_checksum",
           side_effect=DispatcherException('Signature check failed. Unable to get checksum for package.'))
    def test_checksum_none(self, mock_checksum, mock_open, mock_valid_file, mockup) -> None:
        mockup.return_value = 'files', MockTar('tar')
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Unable to get checksum for package.'):
            verify_signature(
                "signature", "path/to/file.tar", MockDispatcherBroker.build_mock_dispatcher_broker(), 384)

    @patch('dispatcher.packagemanager.package_manager._verify_checksum_with_key')
    @patch('dispatcher.packagemanager.package_manager._get_checksum')
    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    @patch('dispatcher.packagemanager.package_manager.load_pem_x509_certificate')
    @patch('builtins.open', new_callable=mock_open, read_data='file content')
    def test_verify_signature_success(self, mock_file, mock_load_cert, mock_extract, 
                                      mock_checksum, mock_verify) -> None:
        files = [MockFile('x'), MockFile('y')]
        mock_extract.return_value = files, MockTar('tar')
        
        mock_checksum.return_value = hashlib.sha384(b'abc').hexdigest()
        
        # Mock the DispatcherBroker
        mock_broker = MagicMock(spec=DispatcherBroker)
        mock_broker.telemetry = MagicMock()
        
         # Mock the load_pem_x509_certificate function to return a mock certificate object
        mock_cert = MagicMock()
        mock_load_cert.return_value = mock_cert

        # Mock the public_key method on the mock certificate object to return a mock public key
        mock_public_key = MagicMock()
        mock_cert.public_key.return_value = mock_public_key

        # Mock the verify method on the mock public key to do nothing (successful verification)
        mock_public_key.verify = MagicMock()

        # Define the signature, path to file, and hash algorithm for the test
        signature = 'signature'
        path_to_file = '/path/to/package.tar'
        hash_algorithm = 384

        # Call the verify_signature function
        verify_signature(signature, path_to_file, mock_broker, hash_algorithm)

        # Assert that the certificate was loaded
        mock_load_cert.assert_called_once()

        # Assert that the public key was used to verify the signature
        mock_verify.assert_called_once()

        # Assert that the telemetry method was called with the success message
        mock_broker.telemetry.assert_called_with('Signature check passed.')

    @patch("dispatcher.packagemanager.package_manager.extract_files_from_tar")
    def test_verify_signature_cert_package_not_found(self, mockup) -> None:
        files = [MockFile('x'), MockFile('y')]
        mockup.return_value = files, None
        with self.assertRaisesRegex(DispatcherException, "Signature check failed. Unsupported file format."):
            verify_signature(
                "signature", "path", MockDispatcherBroker.build_mock_dispatcher_broker(), 384)

    def test_get_checksum_fail(self) -> None:
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Unable to get checksum for package.'):
            _get_checksum(b"abc", 128)

    def test_fetch_success(self) -> None:
        success_result = Result(200, "OK")
        filename = 'file.txt'
        url = canonicalize_uri('https://www.example.com/' + filename)

        with requests_mock.mock() as m:
            response_data = b'data'
            m.get(url.value, content=response_data)
            repo = MemoryRepo(filename)
            self.assertEqual(package_manager.get(
                url, repo, 0, "user", "pass"), success_result)
            self.assertEqual(response_data, repo.get(filename))
            self.assertEqual(package_manager.get(url, MemoryRepo("test"), 0), success_result)

    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.add_from_requests_response',
           side_effect=OSError('Out of Space'))
    def test_fetch_fails_when_out_of_space(self, mock_add) -> None:
        fail_dict = Result(400, "Generic Error")
        filename = 'file.txt'
        url = canonicalize_uri('https://www.example.com/' + filename)

        with requests_mock.mock() as m:
            response_data = 'data'
            m.get(url.value, text=response_data)
            repo = MemoryRepo(filename)
            self.assertEqual(package_manager.get(url, repo, 0), fail_dict)

    def test_get_ext_success(self) -> None:
        self.assertEqual(_get_ext("abc.tar"), 'tar')

    def test_get_ext_empty(self) -> None:
        self.assertEqual(_get_ext(""), "")

    def test_get_checksum_256(self) -> None:
        res = _get_checksum(b'abc', 256)
        self.assertEqual(res, hashlib.sha256(b'abc').hexdigest())

    def test_get_checksum_384(self) -> None:
        res = _get_checksum(b'abc', 384)
        self.assertEqual(res, hashlib.sha384(b'abc').hexdigest())

    def test_get_checksum_invalid(self) -> None:
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Unable to get checksum for package.'):
            _get_checksum(b'abc', 500)

    def test_valid_files_with_files_fail(self) -> None:
        files = [MockFile('test'), MockFile('y')]
        valid_file = _is_valid_file(files)
        self.assertFalse(valid_file)

    def test_verify_checksum_with_key_fail(self) -> None:
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Invalid checksum.'):
            _verify_checksum_with_key(
                None, None, None, MockDispatcherBroker.build_mock_dispatcher_broker())

    def test_verify_checksum_with_key_wrong_size_fail(self) -> None:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Invalid signature.'):
            _verify_checksum_with_key(
                key, None, b'abc', MockDispatcherBroker.build_mock_dispatcher_broker())

    def test_verify_checksum_with_key_wrong_checksum_fail(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072, backend=default_backend())
        pub_key = private_key.public_key()
        with self.assertRaisesRegex(DispatcherException, 'Signature check failed. Invalid signature.'):
            _verify_checksum_with_key(
                pub_key, None, b'abc', MockDispatcherBroker.build_mock_dispatcher_broker())

    def test_verify_checksum_with_key_success(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072, backend=default_backend())
        pub_key = private_key.public_key()
        checksum = hashlib.sha256(b"abcde").hexdigest()
        signature = hexlify(private_key.sign(checksum.encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                                                                   salt_length=padding.PSS.MAX_LENGTH),
                                             hashes.SHA384()))
        try:
            _verify_checksum_with_key(pub_key, signature.decode(encoding='utf-8', errors='strict'), checksum.encode('utf-8'),
                                      MockDispatcherBroker.build_mock_dispatcher_broker())
        except DispatcherException:
            self.fail('Dispatcher exception raised when not expected.')

    def test_parse_config_result_success_a(self) -> None:
        try:
            _parse_config_result(
                '\n http://abc.com\n                http://ci_nginx:80\n\t\t       ', 'http://abc.com')
        except DispatcherException:
            self.fail('Dispatcher exception raised when not expected.')

    def test_parse_config_result_fail_a(self) -> None:
        with self.assertRaisesRegex(DispatcherException,
                                    'Source verification failed.  Source is not in the trusted repository.'):
            _parse_config_result(
                '\n abcdef\n                http://ci_nginx:80\n\t\t       ', '123abcdef')

    def test_parse_config_result_fail_b(self) -> None:
        with self.assertRaisesRegex(DispatcherException,
                                    'Source verification failed.  Source is not in the trusted repository.'):
            _parse_config_result('\n http://abc.com\n                http://ci_nginx:80\n\t\t       ',
                                 'http://def.com')

    def test_parse_config_result_no_response_fail(self) -> None:
        with self.assertRaisesRegex(DispatcherException,
                                    'Source verification failed.  Failure fetching trusted repository.'):
            _parse_config_result(None, 'http://def.com')

    def test_is_source_match_trusted_repo_fail(self) -> None:
        res = _is_source_match_trusted_repo(
            'dispatcher/trustedRepositories:http://def.com', canonicalize_uri(''))
        self.assertFalse(res)

    def test_check_source_matches_trusted_repo_success(self) -> None:
        res = _is_source_match_trusted_repo(
            'dispatcher/trustedRepositories:http://def.com', canonicalize_uri('http://def.com:800'))
        self.assertTrue(res)

    def test_check_source_matches_trusted_repo_fail_null(self) -> None:
        res = _is_source_match_trusted_repo(
            'dispatcher/trustedRepositories:', canonicalize_uri('http://def.com:800'))
        self.assertFalse(res)


if __name__ == '__main__':
    unittest.main()
