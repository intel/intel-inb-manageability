"""
    Interface to Broker class

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class IBroker(ABC):
    """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
    to the command objects and which commands it assigns to the invoker."""

    @abstractmethod
    def publish_telemetry_event(self, nid: str, message: str) -> None:
        """Publish on EVENT_CHANNEL

        @param nid: (for future use)
        @param message: message to publish on channel
        """

        pass

    @abstractmethod
    def publish_telemetry_response(self, nid: str, response: Dict[str, Any]) -> None:
        """Publish on RESPONSE_CHANNEL

        @param nid: (for future use)
        @param response: OTA response to publish on channel
        """

        pass

    @abstractmethod
    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""

        pass
