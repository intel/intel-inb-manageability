"""
    Central configuration/logging service for the manageability framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import json
import logging
from typing import Optional

from inbm_lib.mqttclient.config import DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT, MQTT_KEEPALIVE_INTERVAL
from inbm_lib.mqttclient.mqtt import MQTT

from .commands import Commands
from .constants import AGENT, AGENTS, CLIENT_CERTS, CLIENT_KEYS, COMMAND_CHANNEL, RESPONSE_CHANNEL, \
    STATE_CHANNEL, UPDATE_CHANNEL, ORCHESTRATOR
from .ikeyvaluestore import IKeyValueStore
from .xml_key_value_store import XmlException
from .configuration_exception import ConfigurationException

UNKNOWN = {'rc': 1, 'message': 'Unknown command invoked'}
RESP_OK = {'rc': 0, 'message': 'Command Success'}


logger = logging.getLogger(__name__)


class Broker:  # pragma: no cover
    """Starts the agent and listens for incoming commands on the command channel"""

    def __init__(self, key_value_store: IKeyValueStore, tls: bool = True) -> None:
        self.mqttc = MQTT(AGENT + "-agent", DEFAULT_MQTT_HOST, DEFAULT_MQTT_PORT,
                          MQTT_KEEPALIVE_INTERVAL, env_config=True,
                          tls=tls, client_certs=CLIENT_CERTS, client_keys=CLIENT_KEYS)
        self.mqttc.start()

        self.key_value_store = key_value_store

        self._initialize_broker()

    def _initialize_broker(self) -> None:
        """Initialize module with topics when module starts up"""
        try:
            self.mqttc.publish(f'{AGENT}/state',
                               'running', retain=True)

            logger.debug('Subscribing to: %s', STATE_CHANNEL)
            self.mqttc.subscribe(STATE_CHANNEL, self._on_message)

            logger.debug('Subscribing to: %s', COMMAND_CHANNEL)
            self.mqttc.subscribe(COMMAND_CHANNEL, self._on_command)

        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)

    def _on_message(self, topic, payload, qos):
        """Callback for STATE_CHANNEL"""
        logger.info('Message received: %s on topic: %s', payload, topic)

    def _on_command(self, topic, payload, qos):
        """Callback for COMMAND_CHANNEL"""
        try:
            if payload is not None:
                request = json.loads(payload)
                logger.info('Received command request: %s on topic: %s', request,
                            topic)
                self._execute(request)
        except ValueError as error:
            logger.error('Unable to parse command/request ID. Verify '
                         'request is in the correct format. {}'
                         .format(error))

    def _execute(self, request):
        """Execute MQTT command received on command channel

        @param request: Incoming JSON request
        @return: JSON object representing output of command
            { 'rc': <0/1 - return code>,
            'message': <user friendly message>,
            'cmd': <command invoked>
            }
        """
        request_id = request['id']
        resp = RESP_OK
        try:
            command, headers, path, value, value_string = self._parse_request(
                request)

            if command in [Commands.get_element.name, Commands.set_element.name, Commands.append.name,
                           Commands.remove.name]:
                if value_string:
                    headers = self._get_parent(value_string)
                elif path is not None:
                    headers = self._get_parent(path)

            logger.debug("command : {}, headers : {}, path : {} , value : {} , value_string : {}".format(
                command, headers, path, value, value_string))

            logger.info('%s command sent', command)
            if command == Commands.get_element.name:
                resp = self._get_element_name(headers, path, value_string)
            elif command == Commands.set_element.name:
                self._set_element_name(
                    headers, path, value, value_string)
            elif command == Commands.load.name:
                self._load(path)
            elif command == Commands.append.name:
                self._append(headers, path, value, value_string)
            elif command == Commands.remove.name:
                self._remove(headers, path, value, value_string)
            else:
                logger.error('Unknown command: %s invoked', command)
                resp = UNKNOWN
        except KeyError as e:
            err = f'Key:{e} not found in payload'
            logger.error(err)
            resp = {'rc': 1, 'message': 'Key not present in payload'}
        except XmlException as e:
            err = f'Invalid XML: {e}'
            logger.error(err)
            resp = {'rc': 1, 'message': str(err)}
        except ConfigurationException as err:
            logger.error(err)
            resp = {'rc': 1, 'message': str(err)}
        finally:
            self.mqttc.publish(RESPONSE_CHANNEL +
                               str(request_id), json.dumps(resp))

    @staticmethod
    def _parse_request(request):
        command = request['cmd']
        path = None
        if 'path' in request:
            path = request['path']
        value = None
        if 'value' in request:
            value = request['value']
        headers = None
        if 'headers' in request:
            headers = request['headers']
        value_string = None
        if 'valueString' in request:
            value_string = request['valueString']
        return command, headers, path, value, value_string

    def _get_parent(self, value_string: str) -> Optional[str]:
        value_string = value_string.split(":")[0]
        return self.key_value_store.get_parent(value_string)

    def _append(self, headers: Optional[str],  path: Optional[str], value: Optional[str],
                value_string: Optional[str]) -> None:
        if value is None and value_string is None:
            raise ConfigurationException('Value and value string are not set')

        if path and value:
            if self.key_value_store.append(path=path, value_string=value):
                self.mqttc.publish(UPDATE_CHANNEL + str(path), json.dumps(value))
        elif headers and value_string:
            paths = self.key_value_store.append(
                path=headers, value_string=value_string)
            self._publish_new_values(paths)
        else:
            raise ConfigurationException('Invalid parameters sent to append')

    def _remove(self,  headers: Optional[str], path: Optional[str], value: Optional[str],
                value_string: Optional[str]) -> None:
        if value is None and value_string is None:
            raise ConfigurationException('Please specify the element value')

        if path and value:
            self.key_value_store.remove(path, value)
            self.mqttc.publish(
                UPDATE_CHANNEL + str(path), json.dumps(value))
        elif headers and value_string:
            paths = self.key_value_store.remove(
                headers, value_string=value_string)
            self._publish_new_values(paths)
        else:
            raise ConfigurationException("Invalid parameters sent to remove")

    def _load(self, path: str) -> None:
        self.key_value_store.load(path)
        self.publish_initial_values()

    def _set_element_name(self, headers: Optional[str], path: Optional[str],
                          value: Optional[str], value_string: Optional[str]) -> None:
        """Method used to set a value of an element in XML file
           only if the element is orchestrator set the attribute value otherwise element value

         @headers: parent xml element tag
         @param path: xml element path
         @resp: result
         @value: value to be set
         @value_string: xml element tag whose value needs to be returned
         """
        if value is None and value_string is None:
            raise ConfigurationException('Value was not set')

        if path and value:
            self.key_value_store.set_element(path, value)
            self.mqttc.publish(
                UPDATE_CHANNEL + str(path), json.dumps(value))
        elif headers and value_string:
            if value_string.split(':')[0] == ORCHESTRATOR:
                paths = self.key_value_store.set_element(
                    headers, value_string=value_string, is_attribute=True)
            else:
                paths = self.key_value_store.set_element(
                    headers, value_string=value_string)
            self._publish_new_values(paths)
        else:
            raise ConfigurationException("Invalid parameters sent")

    def _get_element_name(self, headers: Optional[str], path: Optional[str], value_string: Optional[str]):
        """Gets the required value of an element from XML file only if the element is orchestrator return the
        attribute value otherwise element value

         @headers: header xml element tag
         @param path: xml element path
         @value_string: xml element tag whose value needs to be returned
         @return: value of the respective element
         """
        if headers and path:
            if path == ORCHESTRATOR:
                return self.key_value_store.get_element(headers + "/" + path, is_attribute=True)
            return self.key_value_store.get_element(headers + "/" + path)
        if headers and value_string:
            if value_string.split(':')[0] == ORCHESTRATOR:
                return self.key_value_store.get_element(headers, value_string, is_attribute=True)
            return self.key_value_store.get_element(headers, value_string)
        raise ConfigurationException("Invalid request: no path or header")

    def _publish_agent_values(self, agent) -> None:
        children = self.key_value_store.get_children(agent)
        for child in children:
            value = children[child]
            path = agent + '/' + str(child)
            logger.debug(f'Publishing inital agent value on: {UPDATE_CHANNEL}{str(path)}:{json.dumps(value)}')
            self.mqttc.publish(UPDATE_CHANNEL + str(path),
                               json.dumps(value), retain=True)

    def _publish_new_values(self, paths: str) -> None:
        path_list = paths.split(';')
        for i in range(0, len(path_list) - 1):
            list_obj = path_list[i].split(':', 1)
            value = list_obj[1]
            path = list_obj[0]
            logger.debug(f'Publishing new value on: {UPDATE_CHANNEL}{str(path)}:{json.dumps(value)}')
            self.mqttc.publish(
                UPDATE_CHANNEL + str(path), json.dumps(value), retain=True)

    def publish_initial_values(self) -> None:
        """Publish initial values to all the agents"""
        for agent in AGENTS:
            self._publish_agent_values(agent)

    def broker_stop(self) -> None:
        """Shutdown broker, publishing 'dead' event first."""
        self.mqttc.publish(f'{AGENT}/state', 'dead', retain=True)
        self.mqttc.stop()
