"""
    Source Command classes to represent command entered by user.

    # Copyright (C) 2020-2023 Intel Corporation
    # SPDX-License-Identifier: Apache-2.0
"""
from typing import Any

from inbm_lib.constants import SOURCE

from .command import Command
from ..ibroker import IBroker
from ..constants import INBM_INSTALL_CHANNEL, SOURCE_TIME_LIMIT, COMMAND_FAIL
from ..utility import search_keyword
from ..inbc_exception import InbcCode


class SourceCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """Source related command.  Application, OS

        @param broker: Broker object
        """
        super().__init__(SOURCE_TIME_LIMIT, broker, SOURCE)

    def invoke_update(self, args: Any) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments from user
        """
        super()._send_manifest(args, INBM_INSTALL_CHANNEL)

    def search_response(self, payload: Any) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: Any, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)
