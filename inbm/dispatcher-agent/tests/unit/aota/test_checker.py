from unittest import TestCase

from dispatcher.aota.aota_error import AotaError
from dispatcher.aota.checker import check_docker_parameters, is_local_file


class TestChecker(TestCase):
    def test_raise_when_space_in_username(self) -> None:
        try:
            check_docker_parameters("https://www.example.com/", 'us er', 'pwd')
        except AotaError as e:
            self.assertEqual("No spaces allowed in Docker Username/Registry", str(e))

    def test_raise_when_space_in_registry(self) -> None:
        try:
            check_docker_parameters("https  ://www.example.com/", 'user', 'pwd')
        except AotaError as e:
            self.assertEqual("No spaces allowed in Docker Username/Registry", str(e))

    def test_raise_when_password_none(self) -> None:
        try:
            check_docker_parameters("https://www.example.com/", 'user', None)
        except AotaError as e:
            self.assertEqual("Missing docker password in Manifest", str(e))

    def test_raise_when_username_none(self) -> None:
        try:
            check_docker_parameters("https://www.example.com/", None, 'pwd')
        except AotaError as e:
            self.assertEqual("Missing docker username in Manifest", str(e))

    def test_not_raise_when_no_credentials(self) -> None:
        try:
            check_docker_parameters(None, None, None)
        except AotaError as e:
            self.fail("Raised exception when not expected.")

    def test_not_raise_when_all_fields_valid(self) -> None:
        try:
            check_docker_parameters("https://www.example.com/", 'user', 'pwd')
        except AotaError as e:
            self.fail("Raised exception when not expected.")

    def test_is_local_file(self) -> None:
        self.assertEqual(True, is_local_file("file:///abc/def"))
        self.assertEqual(False, is_local_file("https://www.example.com/"))
