"""
    Config Command classes to represent command entered by user.

    # Copyright (C) 2020-2023 Intel Corporation
    # SPDX-License-Identifier: Apache-2.0
"""

from typing import Any
from .command import Command
from ..utility import search_keyword
from ..constants import COMMAND_SUCCESS, COMMAND_FAIL, MAX_TIME_LIMIT, INBM_INSTALL_CHANNEL
from ..inbc_exception import InbcCode
from ..ibroker import IBroker

from inbm_common_lib.constants import CONFIG_CHANNEL, CONFIG_LOAD, CONFIG_APPEND, CONFIG_REMOVE
from inbm_lib.request_message_constants import CONFIGURATION_SUCCESSFUL_MESSAGE_LIST, \
    CONFIGURATION_FAILURE_MESSAGE_LIST


class ConfigCommand(Command):
    def __init__(self, broker: IBroker, command: str) -> None:
        """Configuration related command.  Get, Set, Load

        @param broker: Broker object
        @param command: command name to pass to parent class
        """
        super().__init__(MAX_TIME_LIMIT, broker, command)

    def trigger_manifest(self, args: Any, topic: str):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        # "Configuration get_element command: SUCCESSFUL" is sent by TC node side
        if search_keyword(payload, CONFIGURATION_SUCCESSFUL_MESSAGE_LIST):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, CONFIGURATION_FAILURE_MESSAGE_LIST):
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
            super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class GetConfigCommand(ConfigCommand):
    def __init__(self, broker: IBroker) -> None:
        """Configuration Get command.

       @param broker: Broker object
       """
        super().__init__(broker, 'get')

    def trigger_manifest(self, args: Any, topic: str = INBM_INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke command.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args,  topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class SetConfigCommand(ConfigCommand):
    def __init__(self, broker: IBroker) -> None:
        """Set Configuration Command.

       @param broker: Broker object
       """
        super().__init__(broker, 'set')

    def trigger_manifest(self, args: Any, topic: str = INBM_INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke command.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args,  topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class LoadConfigCommand(ConfigCommand):
    def __init__(self, broker: IBroker) -> None:
        """Configuration Load command.

        @param broker: Broker object
        """
        super().__init__(broker, CONFIG_LOAD)

    def trigger_manifest(self, args: Any, topic: str = INBM_INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class AppendConfigCommand(ConfigCommand):
    def __init__(self, broker: IBroker) -> None:
        """Configuration Append command.
        @param broker: Broker object
        """
        super().__init__(broker, CONFIG_APPEND)

    def trigger_manifest(self, args: Any, topic: str = INBM_INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke config Append.
        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message
        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message
        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class RemoveConfigCommand(ConfigCommand):
    def __init__(self, broker: IBroker) -> None:
        """Configuration Remove command.
        @param broker: Broker object
        """
        super().__init__(broker, CONFIG_REMOVE)

    def trigger_manifest(self, args: Any, topic: str = INBM_INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke config Remove.
        @param args: arguments from user
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, topic)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message
        @param payload: payload received in which to search
        """
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message
        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)
