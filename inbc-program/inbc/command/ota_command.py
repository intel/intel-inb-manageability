"""
    OTA Command classes to represent command entered by user.

    Copyright (C) 2020-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import Any

from .command import Command
from ..constants import COMMAND_SUCCESS, COMMAND_FAIL, FOTA_TIME_LIMIT, SOTA_TIME_LIMIT, POTA_TIME_LIMIT, \
    AOTA_TIME_LIMIT, INBM_INSTALL_CHANNEL
from ..inbc_exception import InbcCode
from ..utility import search_keyword
from ..ibroker import IBroker

from inbm_lib.constants import CACHE, INSTALL_CHANNEL, FOTA, SOTA, POTA, AOTA
from inbm_common_lib.request_message_constants import OTA_SUCCESS_MESSAGE_LIST, SOTA_FAILURE, \
    OTA_FAILURE_MESSAGE_LIST, COMMAND_SUCCESSFUL, SOTA_COMMAND_STATUS_SUCCESSFUL, SOTA_COMMAND_FAILURE, \
    FOTA_INPROGRESS_FAILURE


class PotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """POTA command

        @param broker: Broker object
        """
        super().__init__(POTA_TIME_LIMIT, broker, POTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, INBM_INSTALL_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, [COMMAND_SUCCESSFUL, SOTA_COMMAND_STATUS_SUCCESSFUL]):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        # For FOTA/SOTA failure, Expected "FAILED INSTALL" message, need to update if message changed
        elif search_keyword(payload, OTA_FAILURE_MESSAGE_LIST):
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class AotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """AOTA command

        @param broker: Broker object
        """
        super().__init__(AOTA_TIME_LIMIT, broker, AOTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, INBM_INSTALL_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, OTA_SUCCESS_MESSAGE_LIST):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, OTA_FAILURE_MESSAGE_LIST):
            print("\n AOTA Command Execution FAILED")
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
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

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, INBM_INSTALL_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, OTA_SUCCESS_MESSAGE_LIST):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, OTA_FAILURE_MESSAGE_LIST):
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

        if search_keyword(payload, [SOTA_FAILURE, SOTA_COMMAND_FAILURE]):
            print("\n SOTA Command Execution FAILED")
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)


class FotaCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """FOTA command

        @param broker: Broker object
        """
        super().__init__(FOTA_TIME_LIMIT, broker, FOTA)

    def trigger_manifest(self, args: Any, topic: str = INSTALL_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic
        """
        super().trigger_manifest(args, INBM_INSTALL_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if search_keyword(payload, OTA_SUCCESS_MESSAGE_LIST):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, OTA_FAILURE_MESSAGE_LIST):
            print("\n FOTA Command Execution FAILED")
            if search_keyword(payload, [FOTA_INPROGRESS_FAILURE]):
                self.terminate_operation(COMMAND_FAIL, InbcCode.HOST_BUSY.value)
            else:
                self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
            super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)
