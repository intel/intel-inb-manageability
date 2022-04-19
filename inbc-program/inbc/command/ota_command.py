"""
    OTA Command classes to represent command entered by user.

    # Copyright (C) 2020-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""
from typing import Any
from pathlib import Path

from .command import Command
from ..constants import COMMAND_SUCCESS, COMMAND_FAIL, FOTA_TIME_LIMIT, SOTA_TIME_LIMIT, POTA_TIME_LIMIT, \
    INBM_INSTALL_CHANNEL
from ..inbc_exception import InbcCode
from ..utility import copy_file_to_target_location, search_keyword
from ..ibroker import IBroker

from inbm_vision_lib.constants import CACHE, INSTALL_CHANNEL, FOTA, SOTA, POTA
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_common_lib.request_message_constants import FOTA_SOTA_SUCCESS_MESSAGE_LIST, SOTA_FAILURE, \
    FOTA_SOTA_FAILURE_MESSAGE_LIST, COMMAND_SUCCESSFUL, SOTA_COMMAND_STATUS_SUCCESSFUL, SOTA_COMMAND_FAILURE, \
    SOTA_OVERALL_FAILURE, FLASHLESS_OTA_SUCCESS_MSG


class PotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """POTA command

        @param broker: Broker object
        """
        super().__init__(POTA_TIME_LIMIT, broker, POTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        if not args.nohddl and args.fotapath and args.sotapath:
            # This is only used for HDDL.
            canonical_fota_path = get_canonical_representation_of_path(args.fotapath)
            canonical_sota_path = get_canonical_representation_of_path(args.sotapath)
            args.fotapath = copy_file_to_target_location(Path(canonical_fota_path), CACHE)
            args.sotapath = copy_file_to_target_location(Path(canonical_sota_path), CACHE)
        channel = INBM_INSTALL_CHANNEL if args.nohddl else INSTALL_CHANNEL
        super().trigger_manifest(args, channel)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, [FLASHLESS_OTA_SUCCESS_MSG]):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)

        if search_keyword(payload, [COMMAND_SUCCESSFUL, SOTA_COMMAND_STATUS_SUCCESSFUL]):
            self.count += 1
            if self.count >= self._num_vision_targets * 2:
                self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        # For FOTA/SOTA failure, Expected "FAILED INSTALL" message, need to update if message changed
        elif search_keyword(payload, FOTA_SOTA_FAILURE_MESSAGE_LIST):
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class SotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """SOTA command

        @param broker: Broker object
        """
        super().__init__(SOTA_TIME_LIMIT, broker, SOTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        if not args.nohddl and args.path:
            # This is only used for HDDL.
            canonical_path = get_canonical_representation_of_path(args.path)
            args.path = copy_file_to_target_location(Path(canonical_path), CACHE)
        channel = INBM_INSTALL_CHANNEL if args.nohddl else INSTALL_CHANNEL
        super().trigger_manifest(args, channel)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, FOTA_SOTA_SUCCESS_MESSAGE_LIST):
            self.count += 1
            if self.count >= self._num_vision_targets:
                self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, FOTA_SOTA_FAILURE_MESSAGE_LIST):
            print("\n SOTA Command Execution FAILED")
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
            super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)

        if search_keyword(payload, [SOTA_FAILURE, SOTA_COMMAND_FAILURE, SOTA_OVERALL_FAILURE]):
            print("\n SOTA Command Execution FAILED")
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)


class FotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """FOTA command

        @param broker: Broker object
        """
        super().__init__(FOTA_TIME_LIMIT, broker, FOTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL):
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        if args.path:
            canonical_path = get_canonical_representation_of_path(args.path)
            args.path = copy_file_to_target_location(Path(canonical_path), CACHE)
        channel = INBM_INSTALL_CHANNEL if args.nohddl else INSTALL_CHANNEL
        super().trigger_manifest(args, channel)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, FOTA_SOTA_SUCCESS_MESSAGE_LIST):
            self.count += 1
            if self.count >= self._num_vision_targets:
                self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, FOTA_SOTA_FAILURE_MESSAGE_LIST):
            print("\n FOTA Command Execution FAILED")
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
            super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)
