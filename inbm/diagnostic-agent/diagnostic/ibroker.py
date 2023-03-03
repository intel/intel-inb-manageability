"""
    Interface to Broker class

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from abc import ABC, abstractmethod


class IBroker(ABC):
    """Acts as a receiver in the Command Pattern.  """

    @abstractmethod
    def publish(self, channel: str, message: str) -> None:
        """Publish message on MQTT channel

        @param channel: channel to publish upon
        @param message: message to publish
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""

        pass
