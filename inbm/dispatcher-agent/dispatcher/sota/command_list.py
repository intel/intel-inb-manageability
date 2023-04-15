"""
    Builds and stores a list of valid commands.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from typing import List


class CommandList:

    class CommandObject:
        """Represents a single command

        @param text: text for a single command
        """

        def __init__(self, text: str) -> None:
            self.text = text
            self.status = 'Not Executed'
            self.err: List = []

        def __repr__(self) -> str:
            return self.text

        def get_status(self) -> str:
            """get the status of command"""
            return self.status

        def get_errors(self) -> List:
            """get any error associated with the command"""
            return self.err if self.err else ['N/A']

        def __str__(self) -> str:
            return self.__repr__()

    def __init__(self, cmds: List) -> None:
        """Represents a list of CommandObject

        @param cmds: list of commands to add to command list"""
        self.cmd_list: List = []
        for cmd in cmds:
            cmd_obj = self.CommandObject(cmd)
            self.cmd_list.append(cmd_obj)
