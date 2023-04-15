"""
    Handles polling and publishing telemetry data.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from .constants import *
from .cache_policy import trim_cache

from inbm_common_lib.constants import TELEMETRY_CHANNEL

from . import iahost
from . import software_checker
from . import shared
from . import pms_notification
from .software_bom_list import *
from threading import Thread
import logging
from future import standard_library
from typing import List, Any
from .ipoller import IPoller

standard_library.install_aliases()


logger = logging.getLogger(__name__)


class Poller(IPoller):
    """Class for polling telemetry data."""

    def __init__(self) -> None:

        self._collection_interval_seconds = 60
        self._publish_interval_seconds = 300
        self._max_cache_size = 100
        self._container_health_interval_seconds = self._container_health_temp = 600
        self._with_docker = software_checker.are_docker_and_trtl_on_system()
        self._lower_bound_container_health_interval_seconds = 300
        self._upper_bound_container_health_interval_seconds = 1800
        self._lower_bound_collection_interval_seconds = 30
        self._upper_bound_collection_interval_seconds = 120
        self._lower_bound_publish_interval_seconds = 120
        self._upper_bound_publish_interval_seconds = 480
        self._lower_bound_max_cache_size = 50
        self._upper_bound_max_cache_size = 200
        self._upper_bound_swbom_interval_hours = 168
        self._lower_bound_swbom_interval_hours = 1
        self._swbom_interval_seconds = self._swbom_timer_seconds = 86400
        self._enable_swbom = False
        self._IAHost = False
        self._rm_active = False
        self.pms_notification_registered = False
        self.previous_rm_active_status = False
        self._timer = telemetry_handling.TelemetryTimer(self._collection_interval_seconds,
                                                        self._publish_interval_seconds,
                                                        self._with_docker)

    @staticmethod
    def is_between_bounds(value_desc, actual_value, lower_bound, upper_bound) -> bool:
        """Checks if value is between the upper and lower boundaries.

        @return True if between bounds; otherwise, false.
        """
        try:
            value = int(actual_value)
            if value < lower_bound or value > upper_bound:
                logger.error(value_desc + " needs to be between " +
                             str(lower_bound) + " and " + str(upper_bound))
                return False
            return True
        except ValueError:
            logger.error(value_desc + " value needs to be an integer.")
            return False

    def set_configuration_value(self, val, path) -> None:
        """Sets the class variables with the values retrieved from the configuration agent."""

        if path == COLLECTION_INTERVAL_SECONDS:
            if Poller.is_between_bounds(COLLECTION_INTERVAL_SECONDS, val,
                                        self._lower_bound_collection_interval_seconds,
                                        self._upper_bound_collection_interval_seconds):
                self._timer.set_collect_time(int(val))

        elif path == PUBLISH_INTERVAL_SECONDS:
            if Poller.is_between_bounds(PUBLISH_INTERVAL_SECONDS, val,
                                        self._lower_bound_publish_interval_seconds,
                                        self._upper_bound_publish_interval_seconds):
                self._timer.set_publish_time(int(val))

        elif path == MAX_CACHE_SIZE:
            if Poller.is_between_bounds(MAX_CACHE_SIZE, val, self._lower_bound_max_cache_size,
                                        self._upper_bound_max_cache_size):
                self._max_cache_size = int(val)

        elif path == CONTAINER_HEALTH_INTERVAL_SECONDS:
            if Poller.is_between_bounds(CONTAINER_HEALTH_INTERVAL_SECONDS, val,
                                        self._lower_bound_container_health_interval_seconds,
                                        self._upper_bound_container_health_interval_seconds):
                self._container_health_interval_seconds = int(val)
                self._container_health_temp = self._container_health_interval_seconds

        elif path == ENABLE_SOFTWARE_BOM:
            if val == 'true':
                self._enable_swbom = True
            elif val == 'false':
                self._enable_swbom = False
            else:
                self._enable_swbom = False

        elif path == SOFTWARE_BOM_INTERVAL_HOURS:
            if Poller.is_between_bounds(SOFTWARE_BOM_INTERVAL_HOURS, val,
                                        self._lower_bound_swbom_interval_hours,
                                        self._upper_bound_swbom_interval_hours):
                self._swbom_interval_seconds = int(val) * 60 * 60
                self._swbom_timer_seconds = self._swbom_interval_seconds
        else:
            logger.error('Received path that is not configured: ' + path)

    def loop_telemetry(self, client) -> None:
        """Repeatedly wait collection_interval and collect telemetry.  Whenever publish_interval
        is exceeded, publish telemetry. Verify if Resource Monitor is active and 
        publish PMS telemetry and RAS errors whenever encountered.

        """
        telemetry_bundles: List[Any] = []

        if iahost.is_iahost():
            self._IAHost = True
            self._rm_active = iahost.rm_service_active()
            self.pms_notification_registered = False
            self.previous_rm_active_status = False

        while shared.running:
            telemetry_bundles = trim_cache(telemetry_bundles, self._max_cache_size)
            self._timer.wait_collect(max_sleep_time=1)
            while self._timer.time_to_collect():
                telemetry_bundles.append(
                    telemetry_handling.get_dynamic_telemetry(self._with_docker, self._rm_active))
            while self._timer.time_to_publish():
                logger.debug('Publishing ' + str(len(telemetry_bundles)) +
                             ' saved telemetry bundles.')
                for bundle in telemetry_bundles:
                    telemetry_handling.publish_dynamic_telemetry(client, TELEMETRY_CHANNEL,
                                                                 bundle)
                telemetry_bundles = []

            if self._IAHost:
                self._rm_active = iahost.rm_service_active()
                if self._rm_active and not self.pms_notification_registered:
                    pms = pms_notification.PMSNotification(client)
                    worker = Thread(target=pms.register_pms_notification, args=(self,))
                    worker.setDaemon(True)
                    worker.start()
                    self.previous_rm_active_status = True
                elif self.previous_rm_active_status and not self._rm_active:
                    if self.pms_notification_registered:
                        self.pms_notification_registered = False
                    pms.stop()

            if self._with_docker:
                if self._container_health_temp <= 0:
                    telemetry_handling.get_container_health(client, EVENTS_CHANNEL)
                    self._container_health_temp = self._container_health_interval_seconds
                else:
                    self._container_health_temp -= 1

            if self._enable_swbom:
                if self._swbom_timer_seconds <= 0:
                    publish_software_bom(client, False)
                    self._swbom_timer_seconds = self._swbom_interval_seconds
                else:
                    self._swbom_timer_seconds -= 1
