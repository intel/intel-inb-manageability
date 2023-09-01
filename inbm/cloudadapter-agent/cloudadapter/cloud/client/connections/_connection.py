"""
Abstract base class used by all cloud connection objects.


"""

import abc
from typing import Callable, Optional


class Connection(metaclass=abc.ABCMeta):  # pragma: no cover

    @abc.abstractproperty
    def request_id(self):
        """A readonly property

        @return: (int) Current request ID
        """
        pass

    def get_client_id(self) -> Optional[str]:
        """A readonly property

        @return: (int) Client Id
        """
        pass

    @abc.abstractmethod
    def start(self):
        """Start the connection

        @exception ConnectError: If connecting failed
        """
        pass

    @abc.abstractmethod
    def stop(self):
        """Stop the connection

        @exception DisconnectError: If disconnecting failed
        """
        pass

    @abc.abstractmethod
    def subscribe(self, topic: str, callback: Callable) -> None:
        """Subscribe to a topic on the connection

        @param topic: (str) Connection topic
        @param callback: (Callable) Callback function
        """
        pass

    @abc.abstractmethod
    def publish(self, topic, payload):
        """Publish to a topic on the connection

        @param topic: (str) Connection topic
        @param payload: (str) Message payload
        @exception PublishError: If the publish failed
        """
        pass
