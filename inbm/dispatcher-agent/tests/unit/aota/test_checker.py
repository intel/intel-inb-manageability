from unittest import TestCase

from dispatcher.aota.aota_error import AotaError
from dispatcher.aota.checker import check_docker_parameters, is_local_file


class TestChecker(TestCase):
    def test_raise_when_space_in_username(self):
        try:
            check_docker_parameters("https://www.example.com/", 'us er', 'pwd')
        except AotaError as e:
            self.assertEquals("No spaces allowed in Docker Username/Registry", str(e))

    def test_raise_when_space_in_registry(self):
        try:
            check_docker_parameters("https  ://www.example.com/", 'user', 'pwd')
        except AotaError as e:
            self.assertEquals("No spaces allowed in Docker Username/Registry", str(e))

    def test_raise_when_password_none(self):
        try:
            check_docker_parameters("https://www.example.com/", 'user', None)
        except AotaError as e:
            self.assertEquals("Missing docker password in Manifest", str(e))

    def test_raise_when_username_none(self):
        try:
            check_docker_parameters("https://www.example.com/", None, 'pwd')
        except AotaError as e:
            self.assertEquals("Missing docker username in Manifest", str(e))

    def test_not_raise_when_no_credentials(self):
        try:
            check_docker_parameters(None, None, None)
        except AotaError as e:
            self.fail("Raised exception when not expected.")

    def test_not_raise_when_all_fields_valid(self):
        try:
            check_docker_parameters("https://www.example.com/", 'user', 'pwd')
        except AotaError as e:
            self.fail("Raised exception when not expected.")

    def test_is_local_file(self):
        self.assertEquals(True, is_local_file("file:///abc/def"))
        self.assertEquals(False, is_local_file("https://www.example.com/"))
