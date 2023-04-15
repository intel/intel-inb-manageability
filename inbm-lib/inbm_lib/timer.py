"""
    Module to set the timer.

    Copyright (C) 2019-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from time import sleep
from threading import Thread
from typing import Callable
from typing import Optional

logger = logging.getLogger(__name__)


class Timer(object):

    """Call the callback method when the time is expired

    @param count_down_time: time to count down (in seconds)
    @param callback_method: calling object
    @param node_id: string representing node device id
    @param is_daemon: Set thread deamon.  Default on threads is None.
    If not None, daemon explicitly sets whether the thread is daemonic.
    If None (the default), the daemonic property is inherited from the current thread.
    """

    def __init__(self, count_down_time: int, callback_method: Optional[Callable] = None,
                 node_id: Optional[str] = None, is_daemon: Optional[bool] = None) -> None:
        """If user doesn't pass callback method, user can check timeout value"""
        self._running = True
        self.count_down_time = count_down_time
        self.callback = callback_method
        self.node_id = node_id
        self.current_time = 0
        self.timer = Thread(target=self._start_internal_timer)
        if is_daemon:
            self.timer.daemon = is_daemon

    def start(self) -> None:
        """Start the timer"""
        self.timer.start()

    def stop(self) -> None:
        """Stop the timer"""
        self._running = False

    def get_remaining_wait_time(self) -> int:
        """Get the remaining time to be waited.

        @return: the remaining time to be waited
        """
        return self.count_down_time - self.current_time

    def _start_internal_timer(self) -> None:
        """Start the internal timer that will call the method once count down complete"""
        for count in range(self.count_down_time):
            if not self._running:
                break
            sleep(1)
            self.current_time += 1

        if self._running:
            if self.callback is not None:
                if self.node_id:
                    self.callback(self.node_id)
                else:
                    self.callback()
