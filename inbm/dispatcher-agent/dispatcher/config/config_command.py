"""
    Class for creating Command objects to be sent to the Configuration Agent
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import json

import shortuuid

from .constants import *


class ConfigCommand:
    """
    Basic command class for storing response and creating req/resp topics
    @ivar command: Command to be executed
    """

    def __init__(self, command: str, path: str = None, value: str = None, header_string: str = None, value_string: str = None) -> None:
        self.command = command
        self._id = self._create_request_id()
        self._path = path
        self._value = value
        self._header = header_string
        self._value_string = value_string
        self.response = None

    @staticmethod
    def _create_request_id() -> str:
        """Creates request id using short uuid

        @return: request ID
        """
        return shortuuid.uuid()

    def create_request_topic(self) -> str:
        """Create request topic [configuration-cmd-channel + cmd]

        @return: String representing request topic
        """
        return CONFIGURATION_CMD_CHANNEL + self.command

    def create_response_topic(self) -> str:
        """Create response topic [configuration-resp-channel  + id]

        @return: String representing response topic
        """
        return CONFIGURATION_RESP_CHANNEL + self._id

    def create_payload(self) -> str:
        """Create command payload

        @return: JSON payload [cmd, id, path]
        """

        if self._value_string is None and self._path is None:
            raise ValueError

        payload = {'cmd': self.command, 'id': self._id, 'path': self._path, 'value': self._value,
                   'headers': self._header, 'valueString': self._value_string}

        return json.dumps(payload)
