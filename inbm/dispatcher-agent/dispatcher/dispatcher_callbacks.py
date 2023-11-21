"""
    Helper class to pass common Dispatcher callbacks to OTA threads
    without introducing a dependency on all of Dispatcher

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from dispatcher.dispatcher_broker import DispatcherBroker


class DispatcherCallbacks:
    def __init__(self,
                 broker_core: DispatcherBroker,
                 ) -> None:
        self.broker_core = broker_core
