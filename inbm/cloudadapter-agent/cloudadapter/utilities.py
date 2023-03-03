"""
Utility functions and classes used throughout the cloudadapter module

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from .constants import SLEEP_DELAY
from threading import Thread, Event
from typing import Any, Callable

# ========== Utility classes


class Waiter:

    def __init__(self) -> None:
        """Allow for un/blocking a thread"""
        self._blocker = Event()
        self._value = None

    def finish(self, value: Any = None) -> None:
        """Finish the waiting for blocked thread

        @param value: (Any, optional) Value to pass to the blocked thread
        """
        self._value = value
        self._blocker.set()

    def reset(self) -> None:
        """Reset the state of the Waiter"""
        self._blocker.clear()

    def wait(self) -> Any:
        """Block this thread until finish is called

        @return: (Any) Value passed through finish
        """
        while not self._blocker.wait(timeout=SLEEP_DELAY):
            continue
        return self._value


# ========== Utility functions


def make_threaded(f: Callable) -> Callable:
    """Decorator function that creates daemonic functions

    @param f: (Callable) The function to put on a daemonic thread
    """
    def threaded(*args, **kwargs):
        thread = Thread(target=f, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
    return threaded
