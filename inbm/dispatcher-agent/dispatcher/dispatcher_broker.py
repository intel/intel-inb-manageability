"""
    Helper class to pass common Dispatcher MQTT broker interface to OTA threads
    without introducing a dependency on all of Dispatcher

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import json
import logging
from typing import Any, Optional, Callable

import shortuuid

from dispatcher.constants import AGENT, CLIENT_CERTS, CLIENT_KEYS, COMPLETED, UPDATE_NODE_MQTT_RESPONSE_TIMEOUT
from dispatcher.schedule.sqlite_manager import SqliteManager
from dispatcher.schedule.schedules import Schedule
from dispatcher.dispatcher_exception import DispatcherException
from inbm_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_lib.mqttclient.mqtt import MQTT
from inbm_lib.json_validator import is_valid_json_structure
from inbm_lib.constants import NODE_UPDATE_JSON_SCHEMA_LOCATION

from inbm_common_lib.constants import RESPONSE_CHANNEL, EVENT_CHANNEL, NODE_UPDATE_CHANNEL

logger = logging.getLogger(__name__)


class DispatcherBroker:
    def __init__(self) -> None:  # pragma: no cover
        self.mqttc: Optional[MQTT] = None
        self._is_started = False

    def start(self, tls: bool) -> None:  # pragma: no cover
        """Start the broker.

        @param tls: True if TLS connection is desired"""
        self.mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                          MQTT_KEEPALIVE_INTERVAL, env_config=True,
                          tls=tls, client_certs=CLIENT_CERTS,
                          client_keys=CLIENT_KEYS)
        self.mqttc.start()
        self._is_started = True

    def send_node_update(self, message: str) -> None:
        """Sends node update to local MQTT 'manageability/nodeupdate' channel to be published
        to the cloudadapter where it will be sent as a reques to INBS (service in UDM)       

        @param message: message to be published to the cloud
        """
        logger.debug(f"Sending node update for to {NODE_UPDATE_CHANNEL} with message: {message}")
        
        """Raise TimeoutError if no response is received within the timeout."""
        self.mqtt_publish_and_wait(topic=NODE_UPDATE_CHANNEL, payload=message)

    def _check_db_for_started_job(self) -> Optional[Schedule]:
        sqliteMgr = SqliteManager()
        schedule = sqliteMgr.get_any_started_schedule()
        logger.debug(f"Checking for started schedule in DB: schedule={schedule}")
        if schedule:
            # Change status to COMPLETED
            sqliteMgr.update_status(schedule, COMPLETED)
        
        del sqliteMgr
        return schedule
        
    def send_result(self, message: str, request_id: str = "") -> None:  # pragma: no cover
        """Sends result to local MQTT channel        

        Raises ValueError if request_id contains a slash

        @param message: message to be published to cloud
        @param request_id: if not "", publish to RESPONSE_CHANNEL/request_id instead of RESPONSE_CHANNEL
        """
        if request_id:
            extra_log = f" with id {request_id}"
        else:
            extra_log = ""
        logger.debug(f"Sending result message{extra_log}: {message}")

        if "/" in request_id:
            raise ValueError("id cannot contain '/'")

        if not self.is_started():
            logger.error('Cannot send result: dispatcher core not initialized')
            return

        schedule = self._check_db_for_started_job()
        logger.debug(f"Schedule in Broker Send_result: {schedule}")
        
        if not schedule:
            # This is not a scheduled job
            logger.debug(f"Sending result message with id {request_id}: {message}")
            if request_id != "":
                topic = RESPONSE_CHANNEL + "/" + request_id
                self.mqtt_publish(topic=topic, payload=message)
            else:
                self.mqtt_publish(topic=RESPONSE_CHANNEL, payload=message)
        else:
            # This is a scheduled job 
            
            # TODO: add error handling NEXMANAGE-743
                       
            try:
                # Turn the message into a dict
                message_dict = json.loads(message)
            except json.JSONDecodeError as e:
                logger.error(f"Cannot convert node update formatted message to a dict type.  message={message} error={e}")
                return

            # Update the job_id in the message
            message_dict['job_id'] = schedule.job_id
            
            # Convert the updated message_dict back to a JSON string
            try:
                updated_message = json.dumps(message_dict)
            except (TypeError, OverflowError) as e:
                logger.error(f"Cannot convert Result back to string: {message_dict}. Error: {e}")
                return    

            is_valid = is_valid_json_structure(updated_message, NODE_UPDATE_JSON_SCHEMA_LOCATION)
            if not is_valid:
                logger.error(f"JSON schema validation failed while verifying node_update message: {updated_message}")
                return
       
            logger.debug(f"Sending node update message: {str(updated_message)}")
            self.send_node_update(str(updated_message))        

    def mqtt_publish_and_wait(self, topic: str, payload: Any) -> Any:  # pragma: no cover
        """Publish a message and wait for a response on the appropriate channel within a timeout.
        Raise TimeoutError if no response is received within the timeout."""
        
        if self.mqttc is None:
            raise DispatcherException("Cannot publish on MQTT: client not initialized.")

        request_id = shortuuid.uuid()
        request_topic = topic + "/" + request_id
        response_topic = RESPONSE_CHANNEL + "/" + request_id
        logger.debug("Publishing message to %s with response expected on %s", request_topic, response_topic)
        return self.mqttc.publish_and_wait_response(topic=request_topic,
                                                    response_topic=response_topic,
                                                    payload=payload,
                                                    timeout_seconds=UPDATE_NODE_MQTT_RESPONSE_TIMEOUT)
        
    def mqtt_publish(self, topic: str, payload: Any, qos: int = 0, retain: bool = False) -> None:  # pragma: no cover
        """Publish arbitrary message on arbitrary topic.

        @param topic: topic to publish
        @param payload: message to publish
        @param qos: QoS of the message, 0 by default
        @param retain: Message retention policy, False by default
        """
        if self.mqttc is None:
            raise DispatcherException("Cannot publish on MQTT: client not initialized.")
        self.mqttc.publish(topic=topic, payload=payload, qos=qos, retain=retain)

    def mqtt_subscribe(self, topic: str, callback: Callable[[str, str, int], None], qos: int = 0) -> None:  # pragma: no cover
        """Subscribe to an MQTT topic

        @param topic: MQTT topic to publish message on
        @param callback: Callback to call when message is received;
                         message will be decoded from utf-8
        @param qos: QoS of the message, 0 by default
        """
        if self.mqttc is None:
            raise DispatcherException("Cannot subscribe on MQTT: client not initialized.")
        self.mqttc.subscribe(topic, callback, qos)

    def telemetry(self, message: str) -> None:
        logger.debug('Received event message: %s', message)
        if not self.is_started():
            logger.error('Cannot log event message: dispatcher core not initialized')
        else:
            self.mqtt_publish(topic=EVENT_CHANNEL, payload=message)

    def stop(self) -> None:  # pragma: no cover
        if not self.is_started():
            raise DispatcherException("Cannot stop dispatcher core: not started")
        if self.mqttc is not None:
            self.mqttc.stop()
        self._is_started = False

    def is_started(self) -> bool:  # pragma: no cover
        return self._is_started
