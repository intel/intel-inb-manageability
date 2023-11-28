import unittest
from dispatcher.sota.command_handler import get_command_status
from dispatcher.sota.command_list import CommandList
from dispatcher.sota.constants import FAILED, SUCCESS
from typing import List


class TestCommandHandler(unittest.TestCase):

    def setUp(self) -> None:
        self.command = CommandList(["Test"])
        self.command_object = self.command.cmd_list[0]

    def test_get_command_status_success(self) -> None:
        self.command_object.status = SUCCESS
        cmd_list = [self.command_object]
        self.assertEqual(get_command_status(cmd_list), SUCCESS)

    def test_get_command_status_fail(self) -> None:
        cmd_list = [self.command_object]
        self.assertEqual(get_command_status(cmd_list), FAILED)

    def test_get_command_status_empty_list_fail(self) -> None:
        cmd_list: List[CommandList] = []
        self.assertEqual(get_command_status(cmd_list), FAILED)
