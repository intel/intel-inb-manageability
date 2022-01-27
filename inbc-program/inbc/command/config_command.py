"""
    Config Command classes to represent command entered by user.

    # Copyright (C) 2020-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""

from typing import Any
from pathlib import Path
from .command import Command
from ..utility import copy_file_to_target_location, search_keyword
from ..constants import COMMAND_SUCCESS, COMMAND_FAIL, MAX_TIME_LIMIT, INBM_INSTALL_CHANNEL
from ..inbc_exception import InbcCode
from ..ibroker import IBroker

from inbm_common_lib.constants import CONFIG_CHANNEL, CONFIG_LOAD
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_vision_lib.constants import CACHE_MANAGEABILITY, CONFIG_GET, CONFIG_SET
from inbm_vision_lib.request_message_constants import CONFIGURATION_SUCCESSFUL_MESSAGE_LIST, \
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

    def trigger_manifest(self, args: Any, topic: str) -> None:
        """Trigger the command-line utility tool to invoke command.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        channel = INBM_INSTALL_CHANNEL if args.nohddl else CONFIG_CHANNEL + CONFIG_GET
        super().trigger_manifest(args, channel)

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

    def trigger_manifest(self, args: Any, topic: str) -> None:
        """Trigger the command-line utility tool to invoke command.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        channel = INBM_INSTALL_CHANNEL if args.nohddl else CONFIG_CHANNEL + CONFIG_SET
        super().trigger_manifest(args, channel)

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

    def set_num_vision_targets(self, num_targets: int) -> None:
        """Sets the number of vision targets that are received from vision-agent.

        @param num_targets: Number of targets
        """
        super().set_num_vision_targets(num_targets)

    def trigger_manifest(self, args: Any, topic: str = CONFIG_CHANNEL + CONFIG_LOAD):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments from user
        @param topic: MQTT topic
        """
        canonical_path = get_canonical_representation_of_path(args.path)
        args.path = copy_file_to_target_location(Path(canonical_path), CACHE_MANAGEABILITY)
        super().trigger_manifest(args, CONFIG_CHANNEL + CONFIG_LOAD)

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
