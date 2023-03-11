"""
    Creates a health check command list

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import List, Dict, Any
from .command_pattern import Command


class HealthChecker:
    """Manages all the commands to run"""

    def __init__(self) -> None:
        self.commands: List = []

    def add(self, command: Command) -> None:
        """Adds a command to the command list

        @param command: instance of command object
        """
        self.commands.append(command)

    def run(self) -> Dict[str, Any]:
        """Runs all added commands

        @return: resulting code and message
        """
        for command in self.commands:
            result = command.execute()
            if result['rc'] != 0:
                # return failing message before executing any more commands
                return result

        if len(self.commands) != 1:
            # if we have more than one command, it's an install check.
            result['message'] = 'Install check passed. '

        # return specific success message when running only one command.
        return result
