"""
    Updater class for handling the OTA update

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from typing import List, Optional
from .ota_target import Target
from .data_handler.idata_handler import IDataHandler
from .registry_manager import Registry

from inbm_vision_lib.timer import Timer
from inbm_vision_lib.constants import create_error_message, create_success_message

logger = logging.getLogger(__name__)


class StatusWatcher(object):
    """Manages the Restart request of all requested nodes

    @param targets: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param timer_interval: integer representing the waiting time to complete the request
    """

    def __init__(self, targets: List[Registry], data_handler: IDataHandler, timer_interval: int) -> None:
        self._data_handler_callback = data_handler
        self._targets = self._create_target(targets)
        self._timer = Timer(timer_interval, self._timer_expired)
        self._timer.start()

    def set_done(self, nid: str) -> None:
        """Sets the status of the target to done.

        @param nid: Node ID
        """
        t = self._get_target(nid)
        if t:
            self._data_handler_callback.send_telemetry_response(
                nid, create_success_message('NODE RESTART SUCCESSFUL'))
            t.set_done()

    def is_all_targets_done(self) -> bool:
        """Checks if all targets have completed command

        @return: True if all targets done; otherwise, false.
        """
        for t in self._targets:
            if not t.is_done():
                return False
        logger.debug("Stopping timer as all targets have restarted.")
        self._timer.stop()
        self._data_handler_callback._status_watcher = None  # type: ignore
        return True

    def get_remaining_time(self) -> int:
        """Get the remaining time to wait before performing another request.

        @return: remaining time to wait before being able to perform another request.
        """
        return self._timer.get_remaining_wait_time()

    def _timer_expired(self) -> None:
        """Callback method when timer has expired"""
        logger.debug('Timer expired. Collect all results.')
        self._collect_result()
        self._data_handler_callback._status_watcher = None  # type: ignore

    def _collect_result(self) -> None:
        """Collect results of each node and call data handler API to publish the result.

        TODO: There is no variable in OtaTarget to store last message. Can't retrieve the last
        message.
        TODO: Waiting for further update

        """
        # Remove config file
        logger.info("Number of Targets: %i", len(self._targets))
        logger.info("-------------------------------------------------------------------------")

        for target in self._targets:
            logger.info("deviceID: %s", target.get_node_id())
            logger.info("status: %s", target.is_done())
            logger.info(
                "-------------------------------------------------------------------------")

    @staticmethod
    def _create_target(targets: List[Registry]) -> List[Target]:
        """Create Target object for each target

        @param targets: a list of string representing node's device id
        @return: a list containing otaTarget object
        """
        targets_list = []
        for target in targets:
            targets_list.append(Target(target.device_id))
        return targets_list

    def _get_target(self, nid: str) -> Optional[Target]:
        """Get otaTarget from the list

        @param nid: device id of otaTarget
        @return: otaTarget object or None
        """
        logger.debug("Get information of node with deviceID: %s", nid)
        for target in self._targets:
            if target.get_node_id() == nid:
                logger.debug("Target found.")
                return target
        logger.debug("No target found.")
        return None
