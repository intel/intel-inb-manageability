"""
    HeartbeatTimer

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from time import sleep
from threading import Thread

logger = logging.getLogger(__name__)


class HeartbeatTimer(object):
    """Timer used to tell the node-agent when to send a heartbeat message to the vision-agent.

    @param count_down_time: interval between heartbeat messages.
    @param dh_callback: callback to dataHandler object
    """

    def __init__(self, count_down_time, dh_callback):
        self._running = True
        self.count_down_time = count_down_time
        self.dh_callback = dh_callback
        self.timer = Thread(target=self._start_internal_timer)
        self.timer.start()

    def _start_timer(self) -> None:
        self.timer.start()

    def stop(self) -> None:
        """Stop the timer"""
        self._running = False

    def _start_internal_timer(self) -> None:
        """Start the internal timer that will call the method once count down complete"""
        for count in range(self.count_down_time):
            if not self._running:
                break
            sleep(1)

        if self._running:
            if self.dh_callback is not None:
                self.dh_callback()
