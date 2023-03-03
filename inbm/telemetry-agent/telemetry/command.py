"""
    Class for creating Command objects to be sent to the Diagnostic Agent

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from .constants import *
import shortuuid
import json
from future import standard_library
from typing import Optional

standard_library.install_aliases()


class Command:
    """Basic command class for storing response and creating req/resp topics

    @param command: Command to be executed
    @param size: payload size
    """

    def __init__(self, command: str, size: Optional[str] = None) -> None:
        self.command = command
        self._id = self._create_request_id()
        self.response = None
        self._size = size

    @staticmethod
    def _create_request_id() -> str:
        """Creates request id using short uuid

        @return: request id
        """
        return shortuuid.uuid()

    def create_request_topic(self) -> str:
        """Create request topic [diagnostic-cmd-channel + cmd]

        @return: String representing request topic
        """
        return DIAGNOSTIC_CMD_CHANNEL + self.command

    def create_response_topic(self) -> str:
        """Create response topic [diagnostic-resp-channel  + id]

        @return: String representing response topic
        """
        return DIAGNOSTIC_RESP_CHANNEL + self._id

    def create_payload(self) -> str:
        """Create command payload

        @return: JSON payload [cmd, id, cloud-connector-name]
        """
        payload = {'cmd': self.command, 'id': self._id, 'size': self._size}
        return json.dumps(payload)
