"""
    Manages locking threads.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

import threading
from typing import Optional

logger = logging.getLogger(__name__)


class CountDownLatch:
    """Countdown latch for multi threaded  and async operations.
    Allows one or more threads to wait until a set of operations being performed in other threads
    completes

    @param count: Block until current count reaches 0, Default = 1
    @param tries: Number of attempts, -1 for no limit and None for default
    """

    def __init__(self, count: int = 1, tries: Optional[int] = None) -> None:
        self._count = count
        self._tries = tries
        self._lock = threading.Condition()

    def count_down(self) -> None:
        """Releases lock and notifies waiting processes"""
        self._lock.acquire()
        self._count -= 1
        if self._count <= 0:
            self._lock.notify()
        self._lock.release()

    def await_(self) -> None:
        """Blocks the thread until the latch count reaches zero."""
        tries = self._tries if self._tries else 20
        self._lock.acquire()

        if tries == -1:
            self._lock.wait()
        else:
            while self._count > 0 and tries > 0:
                self._lock.wait(1.0)
                tries -= 1
        self._lock.release()
