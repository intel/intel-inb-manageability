import random
from typing import Tuple
import unittest
from unittest import TestCase
from inbm_common_lib.shell_runner import PseudoShellRunner


class TestRunner(PseudoShellRunner):
    def __init__(self, output: str, err: str, return_code: int) -> None:
        self.__last_commands: list[str] = []
        self.__output = output
        self.__return_code = return_code
        self.__err = err

    def run(self, cmd: str, cwd: str | None = None) -> Tuple[str, str | None, int]:
        self.__last_commands.append(cmd)
        return self.__output, self.__err, self.__return_code

    def last_cmd(self) -> str | None:
        cmds = self.__last_commands
        if len(cmds) == 0:
            return None
        return cmds[len(cmds) - 1]

    def last_commands(self) -> list[str]:
        return self.__last_commands


class TestTestRunner(TestCase):

    def test_test_runner(self) -> None:
        output = str(random.randint(1000, 2000))
        return_code = random.randint(10, 30)
        r = TestRunner(output, "", return_code)
        self.assertEqual(None, r.last_cmd())
        cmd = str(random.randint(1000, 2000))
        self.assertEqual((output, "", return_code), r.run(cmd))
        self.assertEqual(cmd, r.last_cmd())

    def test_test_runner_err(self) -> None:
        r = TestRunner("", "error: ", 0)
        (out, err, code) = r.run("foo")
        self.assertEqual("error: ", err)

    def test_multiple_commands(self) -> None:
        r = TestRunner("", "", 0)
        r.run("abc")
        r.run("def")
        r.run("ghi")
        self.assertEqual(["abc", "def", "ghi"], r.last_commands())


if __name__ == '__main__':
    unittest.main()
