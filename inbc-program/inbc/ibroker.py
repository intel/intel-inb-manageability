"""
Interface to Broker class

Copyright (C) 2020-2022 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

from abc import ABC, abstractmethod


class IBroker(ABC):
    """Interface for the broker object."""

    @abstractmethod
    def publish(self, channel: str, message: str, retain: bool = False) -> None:
        """ Publishes message on channel

        @param channel: channel to publish on
        @param message: message to publish
        @param retain: retain message if true
        """

        pass

    @abstractmethod
    def stop_broker(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""

        pass
