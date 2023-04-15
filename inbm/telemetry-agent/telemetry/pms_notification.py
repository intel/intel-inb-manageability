"""
    RAS Notifications for manageability framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import sys
import time
import json
import logging
from typing import Union
from .constants import *
from . import telemetry_handling
from inbm_common_lib.constants import TELEMETRY_CHANNEL
from inbm_lib.mqttclient.mqtt import MQTT
from telemetry.ipoller import IPoller

logger = logging.getLogger(__name__)


class PmsException(Exception):
    """Class exception Module."""
    pass


class PMSNotification():
    client = MQTT

    def __init__(self, client) -> None:
        PMSNotification.client = client
        self.running = True

    def import_pms_library(self) -> None:
        """Check if PMS Python library can be imported from /usr/lib"""
        sys.path.insert(0, PMS_LIB_PATH)
        try:
            import libPmsPython  # type: ignore
        except (ImportError, ModuleNotFoundError) as error:
            raise PmsException("Unable to locate PMS Python library")

    @staticmethod
    def pms_error_callback(info: Union[str, bytes]) -> None:
        """Notification Callback function to publish message when an error occurs
        """
        alert = {'values': {'resourceAlert': json.loads(info)}, 'type': "dynamic_telemetry"}
        telemetry_handling.publish_dynamic_telemetry(PMSNotification.client, TELEMETRY_CHANNEL,
                                                     alert)

    def register_pms_notification(self, poller: IPoller) -> None:
        """Calls PMS Notification API to notify errors encountered
        """
        try:
            self.import_pms_library()
            from libPmsPython import PmsTelemetry, PmsConnection, PmsConnectionType, TelemetryNotificationRequestType, RasSeverity

            conn = PmsConnection()
            if not conn.Connect(PmsConnectionType.RM_DAEMON):
                raise PmsException("RM Daemon connection failed")

            pms_telemetry = PmsTelemetry(conn)
            return_code = pms_telemetry.SetRASSeverity(RasSeverity.SeverityAll)
            if return_code != 0:
                raise PmsException("Failed to Set RAS Severity level")

            rc = pms_telemetry.RegisterNotificationCallback(
                PMSNotification.pms_error_callback, TelemetryNotificationRequestType.RequestErrorAll)
            if rc != 0:
                raise PmsException("Failed to Register to RAS callback Notifications")
            poller.pms_notification_registered = True
            while self.running:
                time.sleep(2)
        except PmsException as err:
            logger.error(f'{str(err)}. Re-trying PMS RAS registration...')
            err_msg = {'values': {'resourceAlert': str(err)}, 'type': "dynamic_telemetry"}
            telemetry_handling.publish_dynamic_telemetry(PMSNotification.client, TELEMETRY_CHANNEL,
                                                         err_msg)
            poller.pms_notification_registered = False

    def stop(self) -> None:
        """Stops waiting for notifications"""
        self.running = False
