# -*- coding: utf-8 -*-
"""
    Acts as the client in the command pattern for the diagnostic-agent

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import json

from typing import Optional

from diagnostic import constants
from diagnostic.ibroker import IBroker
from diagnostic.event_watcher import EventWatcher
from diagnostic.repeating_timer import RepeatingTimer
from diagnostic.dispatch_command import dispatch_command
from diagnostic.value_bounds_dataclass import ConfigKey
from diagnostic.util import is_between_bounds
from diagnostic.config_dbs import ConfigDbs
from diagnostic.constants import DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC, DEFAULT_DBS_MODE, MANDATORY_SW_LIST, \
    DBS_MODE, DEFAULT_MIN_MEMORY_MB, DEFAULT_MIN_POWER_PERCENT, DEFAULT_MIN_STORAGE_MB, RESPONSE_CHANNEL
from diagnostic.constants import UPPER_BOUND_MEMORY_MB, LOWER_BOUND_MEMORY_MB
from diagnostic.constants import UPPER_BOUND_POWER_PERCENT, LOWER_BOUND_POWER_PERCENT
from diagnostic.constants import UPPER_BOUND_STORAGE_MB, LOWER_BOUND_STORAGE_MB
from diagnostic.constants import UPPER_BOUND_DBS_INTERVAL_SEC, LOWER_BOUND_DBS_INTERVAL_SEC
from diagnostic.constants import MIN_MEMORY_MB, MIN_POWER_PERCENT, MIN_STORAGE_MB
from diagnostic.constants import NETWORK_CHECK, DEFAULT_NETWORK_CHECK, DOCKER_BENCH_SECURITY_INTERVAL_SEC


logger = logging.getLogger(__name__)


class DiagnosticChecker:
    """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
    to the command objects and which commands it assigns to the invoker."""

    def __init__(self, broker: IBroker) -> None:
        """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
        to the command objects and which commands it assigns to the invoker.

        @param broker: Broker instance
        """
        # Default values
        self._broker = broker
        self._min_memory_MB = ConfigKey(
            MIN_MEMORY_MB, LOWER_BOUND_MEMORY_MB, UPPER_BOUND_MEMORY_MB, DEFAULT_MIN_MEMORY_MB)
        self._min_power_percent = ConfigKey(
            MIN_POWER_PERCENT, LOWER_BOUND_POWER_PERCENT, UPPER_BOUND_POWER_PERCENT, DEFAULT_MIN_POWER_PERCENT)
        self._min_storage_MB = ConfigKey(
            MIN_STORAGE_MB, LOWER_BOUND_STORAGE_MB, UPPER_BOUND_STORAGE_MB, DEFAULT_MIN_STORAGE_MB)
        self._network_check = DEFAULT_NETWORK_CHECK
        self._size_path = constants.DEFAULT_MANAGEABILITY_CACHE_PATH
        self.docker_bench_security_interval_sec = ConfigKey(
            DOCKER_BENCH_SECURITY_INTERVAL_SEC, LOWER_BOUND_DBS_INTERVAL_SEC, UPPER_BOUND_DBS_INTERVAL_SEC,
            DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC)
        self._config_key_list = list([self._min_memory_MB, self._min_power_percent,
                                      self._min_storage_MB, self.docker_bench_security_interval_sec])
        self.dbs_mode: ConfigDbs = DEFAULT_DBS_MODE
        self.sw_list: Optional[str] = None
        self.dbs_timer: Optional[RepeatingTimer] = None
        self.event_watcher: Optional[EventWatcher] = None

    def stop_timer(self):
        """Stops the DBS timer when the diagnostic-agent is stopped."""
        if self.dbs_timer:
            self.dbs_timer.stop()

    def set_configuration_value(self, val: str, path: str) -> None:
        """Sets the class variables with the values retrieved from the configuration agent.
        @param val: value to set
        @param path: path in the configuration file to set the value
        """
        logger.debug(f'Attempting to set configuration value: {str(val)} for path {str(path)}')

        matched_path = False
        for key in self._config_key_list:
            if path == key.name:
                matched_path = True
                if is_between_bounds(key.name,
                                     int(val),
                                     int(key.lower_value),
                                     int(key.upper_value)):
                    key.config_value = int(val)

        if path == MANDATORY_SW_LIST:
            matched_path = True
            try:
                self.sw_list = str(val)
            except ValueError:
                logger.error("Invalid software list.")
        if path == NETWORK_CHECK:
            matched_path = True
            self._network_check = str(val)
        if path == DOCKER_BENCH_SECURITY_INTERVAL_SEC:
            if self.dbs_timer:
                self.dbs_timer.stop()
            if self.event_watcher:
                self.dbs_timer = RepeatingTimer(self.docker_bench_security_interval_sec.config_value,
                                                self.event_watcher.run_docker_bench_security)
                # dbs timer will start in _setup_docker_events method.
        if path == DBS_MODE:
            matched_path = True
            if val in ConfigDbs.ON.value:
                self.dbs_mode = ConfigDbs.ON
            elif val in ConfigDbs.OFF.value:
                self.dbs_mode = ConfigDbs.OFF
            elif val in ConfigDbs.WARN.value:
                self.dbs_mode = ConfigDbs.WARN
            else:
                logger.error("Invalid DBS parameter: " + str(val))
            self._setup_docker_events()
        if not matched_path:
            logger.error('Received path that is not configured: ' + path)

    def _setup_docker_events(self) -> None:
        if self._check_sw_mandatory_list('docker') and self.dbs_mode != ConfigDbs.OFF:
            logger.debug("Docker is required  Listening for Docker events.")
            if self.event_watcher:
                self.event_watcher.stop()
            self.event_watcher = EventWatcher(self._broker)
            self.event_watcher.set_dbs_mode(self.dbs_mode)
            logger.debug('DBS check triggered via system boot.')
            self.event_watcher.run_docker_bench_security()
            self.event_watcher.start()
            self.dbs_timer = RepeatingTimer(self.docker_bench_security_interval_sec.config_value,
                                            self.event_watcher.run_docker_bench_security)
            self.dbs_timer.start()
        else:
            if self.event_watcher:
                self.event_watcher.set_dbs_mode(self.dbs_mode)
            logger.debug(f"DBS is set to - {self.dbs_mode}")
            logger.debug("Docker is not required.  Not listening for Docker events.")

    def execute(self, request: str) -> None:
        """Execute MQTT command received on command channel

        @param request: Incoming JSON request
        """
        # Following line will only execute in testing
        assert isinstance(request, dict)  # noqa: S101
        try:
            command = request['cmd']
            request_id = request['id']
            size = request['size']

        except KeyError as e:
            logger.error(f'Key:{e} not found in payload')
            return

        logger.info('%s command sent', command)

        if self.sw_list is None:
            self.sw_list = ""
            logger.error("Invalid software list.")
        resp = dispatch_command(command=command,
                                size=size,
                                size_path=self._size_path,
                                min_memory_mb=self._min_memory_MB.config_value,
                                min_power_percent=self._min_power_percent.config_value,
                                min_storage_mb=self._min_storage_MB.config_value,
                                sw_list=self.sw_list,
                                network_check=self._network_check)

        logger.info(f'Command output: {resp}')
        self._broker.publish(RESPONSE_CHANNEL + str(request_id), json.dumps(resp))

    def _check_sw_mandatory_list(self, software: str) -> bool:
        """Checks if software exists in mandatory software list

        @param software: string value of software
        @return: True if it exists else False. Return False if mandatory software list is None
        """
        if not software:
            logger.debug("No software in mandatory SW list.")
            return False

        if not self.sw_list:
            return False

        return True if software in self.sw_list.strip().replace(' ', '').splitlines() else False
