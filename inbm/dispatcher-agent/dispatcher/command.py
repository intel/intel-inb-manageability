"""
    Class for creating Command objects to be sent to the Diagnostic Agent

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import json

import shortuuid
from inbm_lib.count_down_latch import CountDownLatch

from .constants import *
from .dispatcher_broker import DispatcherBroker


class Command:
    """Basic command class for storing response and creating req/resp topics

    @param command: Command to be executed
    @param size: size of payload; default=None
    """

    def __init__(self, command: str, broker: DispatcherBroker, size=None) -> None:
        self.command = command
        self._id = self._create_request_id()
        self.response = None
        self._size = size
        self._broker = broker
        self.log_info = ""
        self.log_error = ""

    def execute(self) -> None:  # pragma: no cover
        self.log_info = ""
        self.log_error = ""
        latch = CountDownLatch(1)

        # Callback to update the command response
        def on_command(topic: str, payload: str, qos: int) -> None:
            self.log_info += f'Message received: {payload} on topic: {topic}'

            try:
                self.response = json.loads(payload)

            except ValueError as error:
                self.log_error += f'Unable to parse payload: {error}'

            finally:
                # Release lock
                latch.count_down()

        # Subscribe to response channel using the same request ID
        self._broker.mqtt_subscribe(self.create_response_topic(), on_command)

        # Publish command request
        self._broker.mqtt_publish(self.create_request_topic(), self.create_payload())

        latch.await_()

    @staticmethod
    def _create_request_id() -> str:
        """Creates request id using short uuid"""
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
