import requests_mock

from dispatcher.packagemanager.package_manager import is_enough_space_to_download
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.dispatcher_exception import DispatcherException
import unittest
import mock

from inbm_common_lib.utility import canonicalize_uri


class TestIsEnoughSpaceToDownload(unittest.TestCase):

    def setUp(self):
        self.repo = DirectoryRepo('test/directory')
        setattr(self.repo, "exists", mock.Mock())
        setattr(self.repo.exists, "return_value", True)

        setattr(self.repo, "get_free_space", mock.Mock())

    def test_succeeds_with_no_headers_content_size_less_than_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = '1234567890'
            m.get(url.value, text=response_data)
            setattr(self.repo.get_free_space, "return_value", 11)
            result = is_enough_space_to_download(url, self.repo)
            assert result is True

    def test_fails_with_no_headers_content_size_equal_to_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = '1234567890'
            m.get(url.value, text=response_data)
            setattr(self.repo.get_free_space, "return_value", 10)
            result = is_enough_space_to_download(url, self.repo)
            assert result is False

    def test_fails_with_no_headers_content_size_more_than_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = '1234567890'
            m.get(url.value, text=response_data)
            setattr(self.repo.get_free_space, "return_value", 9)
            result = is_enough_space_to_download(url, self.repo)
            assert result is False

    def test_succeeds_with_headers_content_size_less_than_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = '1234567890'
            m.get(url.value, text=response_data, headers={'Content-Length': '9'})
            setattr(self.repo.get_free_space, "return_value", 10)
            result = is_enough_space_to_download(url, self.repo)
            assert result is True

    def test_fails_with_headers_content_size_equal_to_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = '1234567890'
            m.get(url.value, text=response_data, headers={'Content-Length': '10'})
            setattr(self.repo.get_free_space, "return_value", 10)
            result = is_enough_space_to_download(url, self.repo)
            assert result is False

    def test_fails_with_headers_content_size_more_than_space(self):
        url = canonicalize_uri('https://www.example.com/')
        with requests_mock.mock() as m:
            response_data = b'1234567890'
            m.get(url.value, content=response_data, headers={'Content-Length': '11'})
            setattr(self.repo.get_free_space, "return_value", 10)
            result = is_enough_space_to_download(url, self.repo)
            assert result is False

    def test_fails_http_with_username_pasword(self):
        failed = False
        try:
            url = canonicalize_uri('http://www.example.com/')
            with requests_mock.mock() as m:
                response_data = b'1234567890'
                m.get(url.value, content=response_data, headers={'Content-Length': '11'})
                setattr(self.repo.get_free_space, "return_value", 9)
                result = is_enough_space_to_download(
                    url, self.repo, username='user', password='pass')
                assert result is False
        except DispatcherException:
            failed = True
        assert failed


if __name__ == '__main__':
    unittest.main()
