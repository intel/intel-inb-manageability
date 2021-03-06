import random
import unittest
from unittest import TestCase


class TestRunner:

    def __init__(self, output, err, return_code):
        self.__last_commands = []
        self.__output = output
        self.__return_code = return_code
        self.__err = err

    def run(self, cmd):
        self.__last_commands.append(cmd)
        return self.__output, self.__err, self.__return_code

    def last_cmd(self):
        cmds = self.__last_commands
        if len(cmds) == 0:
            return None
        return cmds[len(cmds) - 1]

    def last_commands(self):
        return self.__last_commands


class TestTestRunner(TestCase):

    def test_test_runner(self):
        output = str(random.randint(1000, 2000))
        return_code = str(random.randint(10, 30))
        r = TestRunner(output, "", return_code)
        self.assertEqual(None, r.last_cmd())
        cmd = str(random.randint(1000, 2000))
        self.assertEqual((output, "", return_code), r.run(cmd))
        self.assertEqual(cmd, r.last_cmd())

    def test_test_runner_err(self):
        r = TestRunner("", "error: ", 0)
        (out, err, code) = r.run("foo")
        self.assertEqual("error: ", err)

    def test_multiple_commands(self):
        r = TestRunner("", "", 0)
        r.run("abc")
        r.run("def")
        r.run("ghi")
        self.assertEqual(["abc", "def", "ghi"], r.last_commands())


if __name__ == '__main__':
    unittest.main()
