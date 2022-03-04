"""
    Rollback manager will perform rollback when the flashless update is failed.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import threading
from time import sleep
from typing import List, Optional
import vision.flashless_utility
from inbm_vision_lib.configuration_manager import ConfigurationManager, ConfigurationException
from inbm_vision_lib.constants import create_error_message, create_success_message
from .configuration_constant import ROLLBACK_WAIT_TIME, DEFAULT_ROLLBACK_WAIT_TIME
from .node_communicator.node_connector import NodeConnector
from .broker import Broker
from .constant import AGENT, VISION_ID
from inbm_vision_lib.timer import Timer

logger = logging.getLogger(__name__)


class RollbackManager(object):
    """Starts the agent and listens for incoming commands on the command channel

    @param node_list: list of node id representing the flashless devices
    @param config: instance of ConfigurationManager
    """

    def __init__(self, node_list: List[str], config: ConfigurationManager, node_connector: Optional[NodeConnector],
                 broker: Optional[Broker]) -> None:
        self._flashless_node: List[str] = node_list
        self._config: ConfigurationManager = config
        try:
            self._wait_time: int = int(self._config.get_element([ROLLBACK_WAIT_TIME], AGENT)[0])
        except (ConfigurationException, ValueError) as error:
            logger.debug(
                f"Error while retrieving rollback time: {error}. Use default rollback time {DEFAULT_ROLLBACK_WAIT_TIME}.")
            self._wait_time: int = DEFAULT_ROLLBACK_WAIT_TIME  # type: ignore
        self._node_connector = node_connector
        self._broker = broker
        self._rollback_timer: Timer = Timer(self._wait_time, self._rollback)
        self._rollback_timer.start()
        # Wait 3 seconds so that node will not reboot together.
        sleep(3)

    def _rollback(self) -> None:
        """Perform rollback for all flashless nodes. To rollback the image, it will copy back the backup files,
        reset node and boot with backup image"""
        if self._broker:
            self._broker.publish_telemetry_response(VISION_ID,
                                                    create_error_message(
                                                        "FLASHLESS OTA FAILURE: All nodes wasn't connected back."))
        logger.debug('Execute flashless rollback.')
        vision.flashless_utility.rollback_flashless_files()
        # After copied back the backup files, remove the files in backup folder.
        vision.flashless_utility.remove_backup_files()
        for node in self._flashless_node:
            reset_thread = threading.Thread(target=self._reboot_device, args=(node,))
            reset_thread.daemon = True
            reset_thread.start()

    def _reboot_device(self, nid: str) -> None:
        """Starts the agent and listens for incoming commands on the command channel

        @param nid: string representing node id to be rollback
        """
        if self._node_connector:
            self._node_connector.reset_device(nid)

    def is_all_targets_done(self, node_id: str) -> bool:
        """Checks if all OTA targets have completed OTA.

        @return: True if all targets done; otherwise, false.
        """
        node_list = self._flashless_node.copy()
        for t in node_list:
            if t == node_id:
                logger.debug(f'Node {t} reconnects back.')
                self._flashless_node.remove(t)
                break

        return True if not self._flashless_node else False

    def get_remaining_time(self) -> int:
        """Get the remaining time to wait before performing another request.

        @return: remaining time to wait before being able to perform another request.
        """
        return self._rollback_timer.get_remaining_wait_time()

    def stop(self) -> None:
        """Stop the rollback timer to cancel flashless rollback and remove backup files"""
        # Remove backup files once flashless OTA success
        vision.flashless_utility.remove_backup_files()
        if self._rollback_timer:
            self._rollback_timer.stop()
