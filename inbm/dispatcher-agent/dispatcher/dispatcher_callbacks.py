"""
    Helper class to pass common Dispatcher callbacks to OTA threads
    without introducing a dependency on all of Dispatcher

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Callable

from dispatcher.dispatcher_broker import DispatcherBroker
from dispatcher.update_logger import UpdateLogger

TelemetryFunctionType = Callable[[str], None]
SendResultFunctionType = Callable[[str], None]


class DispatcherCallbacks:
    def __init__(self,
                 broker_core: DispatcherBroker,
                 logger: UpdateLogger
                 ) -> None:
        self.broker_core = broker_core
        self.logger = logger
