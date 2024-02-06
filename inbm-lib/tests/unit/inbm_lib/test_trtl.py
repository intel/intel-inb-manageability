import random
from typing import Tuple
import unittest
from unittest import TestCase
from unittest.mock import patch, Mock

from .test_runner import TestRunner
from inbm_lib.trtl import Trtl

TRTL_APP = '/usr/bin/trtl'


class TestTrtl(TestCase):

    @staticmethod
    def __setup_trtl_test() -> Tuple[int, TestRunner]:
        # This is a test file.  It's alright to run a randomizer
        return_code = random.randint(10, 30) # nosec: B311
        runner = TestRunner("", "", return_code)
        return return_code, runner

    def __check_str_type(self, strn: str) -> bytes:
        encoded_str = bytes(strn + '\n', 'utf-8')
        return encoded_str

    def __check_trtl_output(self,
                            expected: str | None, actual: str | None,
                            expected_code: int | None, actual_code: int | None) -> None:
        self.assertEqual(expected, actual)
        self.assertEqual(expected_code, actual_code)

    def test_trtl_pwd_encoding_bytes(self) -> None:
        res_str = self.__check_str_type("passwordString")
        assert type(res_str) is bytes

    def test_trtl_snapshot(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        (_, _, _) = Trtl(runner, "docker").snapshot("image")
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=snapshot -in=image -am=true",
                                 runner.last_cmd(), 0, 0)
        _, err = Trtl(runner, "docker").get_latest_tag("image")
        self.assertTrue(err is not None)

    def test_stats(self) -> None:
        # This is a test file.  It's alright to run a randomizer
        return_code = random.randint(10, 30) # nosec: B311
        runner = TestRunner("ContainerStats=abc", "", return_code)
        result = Trtl(runner, "docker").stats()
        self.assertEqual("/usr/bin/trtl -type=docker -cmd=stats", runner.last_cmd())
        self.assertEqual('abc', result)

    def test_get_image_by_container_id(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "docker").get_image_by_container_id("123")
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=getimagebycontainerid -id=123",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_import(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").image_import(
            "http:/www.example.com/example.tgz", "image")
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker "
            "-cmd=import -ref=image -src=http:/www.example.com/example.tgz",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_load(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "docker").image_load(
            "/sample/sample.tgz", "sample")
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker -cmd=load -src=/sample/sample.tgz -ref=sample",
            runner.last_cmd(), return_code, result)

    def test_trtl_image_pull_public(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").image_pull_public("image", None)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker -cmd=imagepull -ref=image",
            runner.last_cmd(),
            return_code,
            result)

    @patch.object(Trtl, '_send_password', return_value=("", "", 0))
    def test_trtl_image_pull_private(self, mock_send_password: Mock) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").image_pull_private("image", "docker.hub.com",
                                                                     "user", "pswd")
        mock_send_password.assert_called_once()
        self.assertEqual(result, 0)

    def test_trtl_down(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "compose").down("image")
        self.__check_trtl_output("/usr/bin/trtl -type=compose "
                                 "-cmd=down -in=image",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_up(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "compose").up("image")
        self.__check_trtl_output("/usr/bin/trtl -type=compose "
                                 "-cmd=up -in=image",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_up_with_file(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "compose").up("image", "test.yml")
        self.__check_trtl_output("/usr/bin/trtl -type=compose "
                                 "-cmd=up -in=image -cf=test.yml",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_start(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").start("image", 1)
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=start -in=image -iv=1",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_start_with_option(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "docker", "/bin/bash").start("image", 1, True)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker "
            "-cmd=start -in=image -iv=1 -opt=['/bin/bash']",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_stop(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").stop("image", 1)
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=stop -in=image -iv=1",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_stop_by_id(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").stop_by_id("abc123")
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=stopByID -id=abc123",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_stop_all(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").stop_all("abc12")
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=StopAll -in=abc12",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_image_remove_by_id(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "docker").image_remove_by_id(
            "abc123", True)
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=imageRemoveByID -id=abc123 -f=True",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_exec(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker"). \
            execute("image", 2)
        self.__check_trtl_output("/usr/bin/trtl -type=docker -cmd=exec "
                                 "-in=image -iv=2 -ec=''",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_exec_with_config_params(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker", "{device':['def'],'execcmd':'/sample'}") \
            .execute("image", 1, opt=True)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker "
            "-cmd=exec -in=image -iv=1 -opt=['{device':['def'],"
            "'execcmd':'/sample'}']",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_rollback(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").rollback('a', 5, 'b', 4)
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=rollback -in=a -iv=5 -sn=b -sv=4",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_get_latest_tag(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err = Trtl(
            runner, "docker").get_latest_tag("image")
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=getlatesttag -in=image",
                                 runner.last_cmd(), return_code, err)

    def test_trtl_remove_old_images(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        err = Trtl(runner, "docker").remove_old_images("image")
        self.assertEqual("/usr/bin/trtl -type=docker "
                                 "-cmd=imagedeleteold -in=image",
                                 runner.last_cmd())
        self.assertEqual(None, err)

    def test_trtl_returns_on_compose_remove_old_image(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        err = Trtl(runner, "compose").remove_old_images("abc123")
        self.assertEqual(None, err)

    def test_trtl_commit(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "docker").commit("image", 1)
        self.__check_trtl_output("/usr/bin/trtl -type=docker "
                                 "-cmd=commit -in=image -iv=1",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_remove_container(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        err = Trtl(
            runner,
            "docker").remove_container(
            container_id="123e4",
            force=True)
        self.assertEqual("/usr/bin/trtl -type=docker "
                                 "-cmd=containerRemoveByID -f -id=123e4",
                                 runner.last_cmd())
        self.assertEqual(None, err)

    def test_trtl_single_snapshot(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err = Trtl(runner, "btrfs").single_snapshot(desc="test")
        test_desc = "test"
        self.assertEqual(
            "/usr/bin/trtl -type=btrfs "
            "-cmd=singleSnapshot -description={}".format(test_desc),
            runner.last_cmd())
        self.assertEqual(
            '',
            out)

    def test_trtl_delete_snapshot(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        rc, err = Trtl(runner, "btrfs").delete_snapshot('1')
        self.__check_trtl_output(
            "/usr/bin/trtl -type=btrfs -cmd=deleteSnapshot -iv=1",
            runner.last_cmd(),
            return_code,
            rc)

    def test_trtl_sota_rollback(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        rc, err = Trtl(runner, "btrfs").sota_rollback('1')
        self.__check_trtl_output(
            "/usr/bin/trtl -type=btrfs -cmd=UndoChange -sv=1",
            runner.last_cmd(),
            return_code,
            rc)

    def test_trtl_docker_bench_security(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out = Trtl(runner, "docker").run_docker_bench_security_test()
        self.assertEqual("/usr/bin/trtl -type=docker "
                                 "-cmd=dockerbenchsecurity",
                                 runner.last_cmd())
        self.assertEqual(None, out)

    def test_trtl_image_remove_all(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "compose").image_remove_all(
            "abc123", True)
        self.__check_trtl_output("/usr/bin/trtl -type=compose "
                                 "-cmd=ImageRemoveAll -in=abc123 -f=True",
                                 runner.last_cmd(), return_code, result)

    def test_trtl_list(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        err, _ = Trtl(runner, "compose").list("abc")
        self.assertEqual(
            "/usr/bin/trtl -type=compose -cmd=list -in=abc",
            runner.last_cmd())
        self.assertEqual(None, err)

    def test_trtl_compose_image_pull_public_with_image_tag(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "compose").image_pull_public("images", None, None)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=compose -cmd=pull -ref=images",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_compose_image_pull_public_with_image_and_registry_tags(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "compose").image_pull_public("images", "docker.io", None)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=compose -cmd=pull -ref=images",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_docker_image_pull_public_with_image_and_registry_tags(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(
            runner, "docker").image_pull_public("images", "docker.io", None)
        self.__check_trtl_output(
            "/usr/bin/trtl -type=docker -cmd=imagepull -ref=docker.io/images",
            runner.last_cmd(),
            return_code,
            result)

    def test_trtl_compose_pull_with_file(self) -> None:
        return_code, runner = self.__setup_trtl_test()
        out, err, result = Trtl(runner, "compose").image_pull_public("image", None, "test.yml")
        self.__check_trtl_output("/usr/bin/trtl -type=compose "
                                 "-cmd=pull -cf=test.yml -ref=image",
                                 runner.last_cmd(), return_code, result)


if __name__ == '__main__':
    unittest.main()
