"""
Responsible for publishing messages to the cloud, doing some preparsing
before calling appropriate Adapter methods

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from typing import Dict

from ..exceptions import PublishError
from ..constants import LOGGED_TELEMETRY
from .adapters.adapter import Adapter
import datetime
import time
import json

import logging
logger = logging.getLogger(__name__)


class CloudPublisher:
    """Publishes data to the cloud

    @param adapter: (Adapter) The cloud adapter to use
    """

    def __init__(self, adapter: Adapter) -> None:
        self._adapter = adapter

    def publish_event(self, message: str) -> None:
        """Publish an event to the cloud

        @param message: (str) The event's message to send
        """
        try:
            self._adapter.publish_event(message)
        except PublishError as e:
            logger.error(str(e))

    def publish_telemetry(self, message: str) -> None:
        """Send dynamic/static telemetry to the cloud

        @param message: (str) JSON formatted telemetry message to send
        """
        json_message: Dict = {}
        try:
            json_message = json.loads(message)
        except ValueError:
            logger.error("Issue parsing telemetry JSON: %s", message)
            return

        telemetry_type = json_message.get("type")
        if telemetry_type not in ("dynamic_telemetry", "static_telemetry"):
            logger.error("Telemetry JSON is missing telemetry_type: %s", message)
            return

        values = json_message.get('values', {})
        for key, value in values.items():
            if key in LOGGED_TELEMETRY:
                self.publish_event(f"{key}: {value}")
            if telemetry_type == "dynamic_telemetry":
                timestamp = int(json_message.get('timestamp', time.time()))
                timestamp_utc = datetime.datetime.utcfromtimestamp(timestamp)
                try:
                    self._adapter.publish_telemetry(key, value, timestamp_utc)
                except PublishError as e:
                    logger.error(str(e))
            elif telemetry_type == "static_telemetry":
                try:
                    self._adapter.publish_attribute(key, value)
                except PublishError as e:
                    logger.error(str(e))
