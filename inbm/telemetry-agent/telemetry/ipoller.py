"""
    Interface to Poller class

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from abc import ABC, abstractmethod


class IPoller(ABC):
    """Class for polling telemetry data."""

    def __init__(self) -> None:
        self.pms_notification_registered: bool

    @abstractmethod
    def set_configuration_value(self, val, path) -> None:
        """Sets the class variables with the values retrieved from the configuration agent."""
        pass

    @abstractmethod
    def loop_telemetry(self, client) -> None:
        """Repeatedly wait collection_interval and collect telemetry.  Whenever publish_interval
        is exceeded, publish telemetry. Verify if Resource Monitor is active and
        publish PMS telemetry and RAS errors whenever encountered.

        """
        pass
