"""
Abstract base class used by all message handler objects.
Handlers process inbound messages from a given Connection,
triggering any callbacks parsed from the message.


"""


from typing import Callable
import abc


class Handler(metaclass=abc.ABCMeta):  # pragma: no cover

    @abc.abstractmethod
    def bind(self, key: str, callback: Callable) -> None:
        """Bind a callback to a certain method name
        The callback has the signature: (**kwargs) -> (str)
            (**kwargs): Keys/types are documented per action function
            (str): The success status and an accompanying message

        @param key:      (str) Method key to bind to
        @param callback: (str) Method callback to trigger
        """
        pass
