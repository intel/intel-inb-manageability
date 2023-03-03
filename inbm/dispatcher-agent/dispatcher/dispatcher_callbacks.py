"""
    Helper class to pass common Dispatcher callbacks to OTA threads
    without introducing a dependency on all of Dispatcher

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Callable, Optional

from dispatcher.dispatcher_broker import DispatcherBroker

TelemetryFunctionType = Callable[[str], None]
InstallCheckFunctionType = Callable[..., None]  # all args optional
SendResultFunctionType = Callable[[str], None]


class DispatcherCallbacks:
    def __init__(self,
                 install_check: InstallCheckFunctionType,
                 broker_core: DispatcherBroker,
                 sota_repos: Optional[str],
                 proceed_without_rollback: bool
                 ) -> None:
        self.install_check = install_check
        self.sota_repos = sota_repos
        self.broker_core = broker_core
        self.proceed_without_rollback = proceed_without_rollback
