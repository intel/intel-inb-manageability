"""
Utility functions and classes used throughout the cloudadapter module

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

import logging
import os

from .constants import SLEEP_DELAY, UCC_FILE, UCC_ENABLED_FLAG
from threading import Thread, Event
from typing import Any, Callable

logger = logging.getLogger(__name__)
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


def is_ucc_mode() -> bool:
    """Reads a file to determine if the cloud adapter is connected to the UCC broker to help determine
    what topics to subscribe to.  If the file is not found, UCC mode will be False."""
    if not os.path.exists(UCC_FILE):
        logger.debug('UCC flag file was not found.  Not using UCC broker and UCC Service Agent.')
        return False

    if os.path.islink(UCC_FILE):
        logger.debug(f"Security error: UCC flag file is a symlink")
        raise IOError("Security error: UCC flag file is a symlink")

    try:
        with open(UCC_FILE) as f:
            flag = f.readline().rstrip('\n')
            return True if flag == UCC_ENABLED_FLAG else False
    except OSError as e:
        raise IOError(f'Error {e} reading the file {UCC_FILE}')
