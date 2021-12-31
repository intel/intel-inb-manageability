"""
    OtaTarget stores the device id, update status and error messages of the node.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging

from abc import ABC
from .request_status import RequestStatus

logger = logging.getLogger(__name__)


class Target(ABC):
    """Parent class for storing node agent's status information"""

    def __init__(self, node_id: str) -> None:
        self._node_id = node_id
        self._is_done = False

    def get_node_id(self):
        """Return node's device id"""
        return self._node_id

    def set_done(self) -> None:
        """Sets the is_done variable to True"""
        logger.debug("Setting to done -> node: {}")
        self._is_done = True

    def is_done(self) -> bool:
        """Returns the is_done variable status

        @return: True if target is done; otherwise, false
        """
        return self._is_done


class OtaTarget(Target):
    """Class for storing node agent's OTA update information"""

    def __init__(self, node_id: str) -> None:
        super(OtaTarget, self).__init__(node_id)
        self._error = "None"
        self._status = RequestStatus.NoneState
        self.current_sent_file_index = 0

    def get_error(self) -> str:
        """Return node's error message"""
        return self._error

    def get_status(self):
        """Return node's update status"""
        return self._status

    def get_file_index(self) -> int:
        """Return node's current file index"""
        return self.current_sent_file_index

    def set_error(self, error) -> None:
        """Set error message of node agent

        @param error: a string contains the error message dng OTA update
        """
        self._error = error

    def set_file_index(self, index: int) -> None:
        """Set current sent file index of node agent

        @param index: integer representing number of file sent
        """
        self.current_sent_file_index = index

    def update_status(self, status) -> None:
        """Set OTA update status of node agent

        @param status: RequestStatus enumeration represents different stage of ota update's status
        """
        self._status = status
