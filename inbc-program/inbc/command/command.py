"""
    Command classes to represent command entered by user.

    # Copyright (C) 2020-2022 Intel Corporation
    # SPDX-License-Identifier: Apache-2.0
"""

import os
import logging
from typing import Any, Optional
from abc import ABC, abstractmethod
from time import sleep
from inbc import shared

from ..constants import COMMAND_SUCCESS, COMMAND_FAIL, MAX_TIME_LIMIT, VISION_SERVICE_PATH
from ..ibroker import IBroker
from ..inbc_exception import InbcCode
from ..utility import search_keyword, is_vision_agent_installed

from inbm_vision_lib.timer import Timer
from inbm_vision_lib.constants import DEVICE_STATUS_CHANNEL, RESTART, QUERY, \
    XLINK_SIMULATOR_PC_LIB_PATH, QUERY_CHANNEL, STATUS_CHANNEL, RESTART_CHANNEL, NODE
from inbm_common_lib.request_message_constants import COMMAND_SUCCESSFUL, DYNAMIC_TELEMETRY, \
    RESTART_SUCCESS, RESTART_FAILURE, QUERY_SUCCESS, QUERY_FAILURE, OTA_IN_PROGRESS, ACTIVE_NODE_NOT_FOUND, \
    ELIGIBLE_NODE_NOT_FOUND, QUERY_HOST_SUCCESS, QUERY_HOST_FAILURE, QUERY_HOST_KEYWORD
from inbm_lib.constants import HOST_QUERY_CHANNEL

logger = logging.getLogger(__name__)


class Command(ABC):
    """Base class for command objects

    @param timer_limit: max time for timer to wait for command completion
    @param broker: Broker object
    @param cmd_type: name of command to execute
    """

    def __init__(self, timer_limit: int, broker: IBroker, cmd_type: str) -> None:
        self._update_timer = Timer(timer_limit, self._timer_expired, is_daemon=True)
        self._is_vision_agent_installed = is_vision_agent_installed()
        if self._is_vision_agent_installed:
            self._status_timer = Timer(10, self._vision_agent_not_active, is_daemon=True)
        self._broker = broker
        self._cmd_type = cmd_type
        """num_vision_targets is used to determine the number of expected successful messages to be received 
           from vision-agent.  After the OTA command is triggered the vision-agent sends the number of targets 
           to be updated."""
        self._num_vision_targets = 1
        self._is_vision_agent_running = False
        self.count = 0
        self._target_type: Optional[str] = None

    def set_target_type(self, target_type: str) -> None:
        """Sets the target type.

        @param target_type: target name to be set.
        """
        self._target_type = target_type

    def set_num_vision_targets(self, num_targets: int) -> None:
        """Sets the number of targets in the request.

        @param num_targets: number of targets
        """
        self._num_vision_targets = num_targets

    def get_num_vision_targets(self) -> int:
        """Gets the number of eligible targets

        @return number of targets
        """
        return self._num_vision_targets

    def set_is_vision_agent_running(self, is_running: bool):
        """Sets the running state of vision-agent to running.  True if vision-agent is running; otherwise, False.

        @param is_running: running state of the vision-agent
        """
        self._is_vision_agent_running = is_running

    def stop_timer(self):
        """Stops the timer which is waiting for the command to execute."""
        self._update_timer.stop()

    @abstractmethod
    def trigger_manifest(self, args: Any, topic: str) -> None:
        """Trigger the command-line utility tool to invoke update.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic to publish the manifest.
        """
        manifest = args.func(args)
        if self._is_vision_agent_installed:
            self._broker.publish(STATUS_CHANNEL, "Are you running?")
            self._status_timer.start()
            sleep(1)
        self._broker.publish(topic, manifest)
        self._update_timer.start()

    @abstractmethod
    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if self._is_vision_agent_installed:
            self._search_for_busy(payload)
            self._search_for_error(payload)
        elif search_keyword(payload, ["SUCCESSFUL"]):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        else:
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)

    @abstractmethod
    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        if not search_keyword(payload, [DYNAMIC_TELEMETRY]):
            logger.info('Message received: %s on topic: %s', payload, topic)

        if search_keyword(payload, ["/usr/bin/mender -install"]):
            print("\n Flashing mender file. This will take several minutes...")

    def _search_for_busy(self, payload: str) -> None:
        if search_keyword(payload, [OTA_IN_PROGRESS]):
            self.terminate_operation(COMMAND_FAIL, InbcCode.HOST_BUSY.value)

    def _search_for_error(self, payload: str) -> None:
        if search_keyword(payload, [ACTIVE_NODE_NOT_FOUND, ELIGIBLE_NODE_NOT_FOUND]):
            self.terminate_operation(COMMAND_FAIL, InbcCode.NODE_NOT_FOUND.value)

    def _timer_expired(self) -> None:
        """Callback method when timer has expired"""
        logger.debug('\n Timer expired. INBC terminating')
        self.terminate_operation(COMMAND_FAIL, InbcCode.COMMAND_TIMED_OUT.value)

    def _vision_agent_not_active(self) -> None:
        """Check vision-agent status and stop INBC when vision-agent is not running"""
        if not self._is_vision_agent_running:
            logger.error("vision-agent is not running. Please start vision-agent service.")
            self.terminate_operation(
                COMMAND_FAIL, InbcCode.VISION_AGENT_UNAVABILABLE.value)

    def terminate_operation(self, status: str, return_code: int) -> None:
        """Stop INBC after getting expected response from vision-agent

        @param status: success or failure response
        @param return_code: INBC return code
        """
        # Wait 3 seconds to receive further messages from the vision-agent.
        # If it is in IT environment, skip the wait time
        if self._is_vision_agent_installed:
            with open(VISION_SERVICE_PATH, 'r') as vision_service_file:
                if "XLINK_SIMULATOR=False" in vision_service_file.read():
                    # Not inside IT environment
                    sleep(3)

            if not os.path.exists(XLINK_SIMULATOR_PC_LIB_PATH):
                sleep(3)
        if status == COMMAND_SUCCESS:
            print(f"\n {self._cmd_type} Command Execution is Completed")
        elif status == COMMAND_FAIL:
            print(f"\n {self._cmd_type} Command Execution FAILED")
            shared.exit_code = abs(return_code)
        logger.info("INBC code: {0}".format(return_code))
        shared.running = False
        self._update_timer.stop()


class RestartCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """Restart command

        @param broker: Broker object
        """
        super().__init__(MAX_TIME_LIMIT, broker, RESTART)

    def trigger_manifest(self, args: Any, topic: str = RESTART_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke restart.

        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic to publish the manifest.
        """
        super().trigger_manifest(args, RESTART_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        # Expected "Restart SUCCESSFUL" message, need to update if message changed
        if search_keyword(payload, [RESTART_SUCCESS]):
            print("\n Device will restart after one minute.")
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        elif search_keyword(payload, [RESTART_FAILURE]):
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        else:
            super().search_response(payload)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        super().search_event(payload, topic)


class QueryCommand(Command):
    def __init__(self, broker: IBroker) -> None:
        """Query command

        @param broker: Broker object
        """
        super().__init__(MAX_TIME_LIMIT, broker, QUERY)
        self._success_code: Optional[int] = None

    def trigger_manifest(self, args: Any, topic: str = QUERY_CHANNEL) -> None:
        """Trigger the command-line utility tool to invoke query request.
        If target type is None, it publishes the request to the channel subscribed by INBM's agent.
        @param args: arguments passed to command-line tool.
        @param topic: MQTT topic to publish the manifest.
        """
        if self._target_type == NODE:
            super().trigger_manifest(args, QUERY_CHANNEL)
        else:
            super().trigger_manifest(args, HOST_QUERY_CHANNEL)

    def search_response(self, payload: str) -> None:
        """Search for keywords in response message

        @param payload: payload received in which to search
        """
        if self._target_type != NODE:
            self.search_host_response(payload)
        else:
            if search_keyword(payload, [QUERY_SUCCESS]):
                self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
            elif search_keyword(payload, [QUERY_FAILURE]):
                self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
            else:
                super().search_response(payload)

    def search_host_response(self, payload: str) -> None:
        """If it is query for host, inbc will not exit immediately, it will wait for query result.

        @param payload: payload received in which to search
        """
        if search_keyword(payload, [QUERY_HOST_SUCCESS]):
            self._success_code = InbcCode.SUCCESS.value
            print("\n Waiting for last query result...")
        elif search_keyword(payload, [QUERY_HOST_FAILURE]):
            self._success_code = InbcCode.FAIL.value
            self.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)

    def search_event(self, payload: str, topic: str) -> None:
        """Search for keywords in event message

        @param payload: payload received in which to search
        @param topic: topic from which message was received
        """
        if self._target_type != NODE:
            self.search_host_event(payload)
        else:
            super().search_event(payload, topic)

    def search_host_event(self, payload: str) -> None:
        """If it is query for host, search for keywords message like queryEndResult.
        If it didn't receive the keyword, INBC will exit with timeout.

        @param payload: payload received in which to search
        """
        print("\n" + payload)
        if search_keyword(payload, [QUERY_HOST_KEYWORD]):
            self.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
