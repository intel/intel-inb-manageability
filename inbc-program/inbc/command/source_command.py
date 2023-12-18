"""
    Source Command classes to represent command entered by user.

    # Copyright (C) 2020-2023 Intel Corporation
    # SPDX-License-Identifier: Apache-2.0
"""
from typing import Any

from inbm_lib.constants import SOURCE

from .command import Command
from ..ibroker import IBroker
from ..constants import SOURCE_TIME_LIMIT


class SourceCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """Source related command.  Application, OS

        @param broker: Broker object
        """
        super().__init__(SOURCE_TIME_LIMIT, broker, SOURCE)

    def trigger_manifest(self, args: Any, topic: str) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, topic)

    def search_response(self, payload: Any) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        # TODO: Add responses to wait for
        super().search_response(payload)

    def search_event(self, payload: Any, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)
