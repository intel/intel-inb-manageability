"""
    Timer utilizing thr Python threading.Timer class

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from threading import Timer

logger = logging.getLogger(__name__)


class RepeatingTimer:
    """Creates a timer that repeats

    @param interval_time: in seconds to wait for timer to expire
    @param f: callback function
    """

    def __init__(self, interval_time, f):
        self._interval_time = interval_time
        self.f = f
        self._timer = None

    def _callback(self) -> None:
        """Runs the callback method and restarts the timer"""
        self.f()
        self.start()

    def start(self) -> None:
        """Creates a new timer and starts it"""
        logger.debug(f'Creating new Timer with interval of {self._interval_time} seconds')
        self._timer = Timer(self._interval_time, self._callback)
        self._timer.start()

    def stop(self) -> None:
        """Stops the Timer"""
        if self._timer is None:
            logger.error("Tried to stop an uninitialized RepeatingTimer.")
        else:
            logger.debug("Stopping the DBS timer.")
            self._timer.cancel()
