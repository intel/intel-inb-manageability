# -*- coding: utf-8 -*-
"""
    Class to communication between Broker, Xlink Manager, Invoker, Heartbeat Timer, Parser and
    Command Objects

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os.path
import shutil
from typing import Optional, Any
from pathlib import Path

from inbm_common_lib.validater import configuration_bounds_check
from inbm_vision_lib.invoker import Invoker
from inbm_vision_lib import checksum_validator
from inbm_vision_lib.configuration_manager import ConfigurationManager
from inbm_vision_lib.constants import NODE, NODE_CLIENT, CACHE, CACHE_MANAGEABILITY, SecurityException, \
    XmlException
from inbm_vision_lib.xml_handler import XmlHandler

from . import idata_handler, inode
from .command.command import Command, NodeCommands, RequestToDownloadCommand, SendHeartbeatCommand, \
    SendManifestCommand, RegisterCommand, SendDownloadStatusCommand, SendTelemetryEventCommand, SendOtaResultCommand, \
    SendOtaClientConfigurationCommand
from .command.configuration_command import ConfigValuesCommand, LoadConfigCommand, SendConfigResponseCommand
from .constant import INVOKER_QUEUE_SIZE, GET_ELEMENT, SET_ELEMENT, \
    REGISTRATION_RETRY_TIMER_SECS, REGISTRATION_RETRY_LIMIT, LOAD, APPEND, REMOVE, \
    XLINK_SCHEMA_LOCATION, KEY_DICTIONARY, HEARTBEAT_RESPONSE_TIMER_SECS, CONFIG_REGISTRATION_RETRY_TIMER_SECS, \
    CONFIG_REGISTRATION_RETRY_LIMIT, CONFIG_HEARTBEAT_RESPONSE_TIMER_SECS
from .heartbeat_timer import HeartbeatTimer
from .node_exception import NodeException
from .xlink_parser import XLinkParser


logger = logging.getLogger(__name__)


class DataHandler(idata_handler.IDataHandler):
    """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
    to the command objects and which commands it assigns to the invoker.

    @param node_callback: Callback to the Node object
    """

    def __init__(self, node_callback: inode.INode, config_callback: ConfigurationManager) -> None:
        """Init DataHandler."""
        self.node_callback = node_callback
        self._invoker = Invoker(INVOKER_QUEUE_SIZE)
        self._config = config_callback
        self._heartbeat: Optional[HeartbeatTimer] = None
        self._heartbeat_interval: Optional[int] = None
        self._nid: Optional[str] = None
        self._timer: Optional[HeartbeatTimer] = None
        self._retry_limit: int = 0
        self._retry_interval: int = 0
        self._retry_timer: int = 0
        self._heartbeat_response: int = CONFIG_HEARTBEAT_RESPONSE_TIMER_SECS.default_value
        self._heartbeat_response_timer: Optional[HeartbeatTimer] = None
        self.load_config_file()
        self.file_name = None

    def get_nid(self) -> Optional[str]:
        """return node id of agent"""
        return self._nid if self._nid else None

    def load_config_file(self) -> None:
        """Load the default value from intel_manageability_node.conf file"""
        children = self._config.get_children(NODE)
        self.publish_config_value(children)

    def receive_mqtt_message(self, payload: str) -> None:
        """Publish message to vision-agent when receive message from EVENT_CHANNEL and TELEMETRY_CHANNEL"""
        command = SendTelemetryEventCommand(self._nid, self.node_callback.get_xlink(), payload)
        self._invoker.add(command)

    def receive_mqtt_result(self, payload) -> None:
        """Publish message to vision-agent when receive message from RESPONSE_CHANNEL or CONFIGURATION_RESP_CHANNEL """
        # Node will receive config response from node_client. In that case, it uses SendConfigResponseCommand.
        command = SendConfigResponseCommand(self._nid, self.node_callback.get_xlink(), payload) \
            if payload.find("Configuration") > 0 else \
            SendOtaResultCommand(self._nid, self.node_callback.get_xlink(), payload)
        self._invoker.add(command)

    def _validate_xlink_message(self, xlink_message: str) -> None:
        """Check the validity of xlink message.

        @param xlink_message: xlink manifest to be validated
        """
        try:
            XmlHandler(xml=xlink_message, schema_location=XLINK_SCHEMA_LOCATION)
        except XmlException as error:
            raise NodeException(
                "Xlink message validation fail. Error: {0}".format(error))

    def receive_xlink_message(self, message: str) -> None:
        """Performs the following steps:
        1. Parse the xml received from vision-agent
        2. Determine which command it is
        3. Create the correct Command object
        4. Add the Command to Invoker
        """
        logger.debug('Received message from xlink: {}'.format(message))
        try:
            msg = message.rsplit("::", 1)
            checksum_hash = msg[1]
            actual_msg = msg[0]
            checksum_validator.validate_message(checksum_hash, actual_msg)
            self._validate_xlink_message(actual_msg)
            cmd, nid, dictionary, revised_manifest, target_type = XLinkParser().parse(actual_msg)
            logger.debug("cmd : {}".format(cmd))

            if nid == self._nid:
                if cmd in [NodeCommands.get_configuration.value, NodeCommands.set_configuration.value, LOAD,
                           NodeCommands.append_configuration.value, NodeCommands.remove_configuration.value]:
                    command = self._process_configuration_command(cmd, target_type, dictionary)
                else:
                    command = self._process_command(cmd, revised_manifest, dictionary)

                if command:
                    self._invoker.add(command)
                else:
                    if cmd is NodeCommands.REGISTER_RESPONSE.value:
                        logger.debug('Send Heartbeat every %s sec', dictionary)
                    elif cmd is NodeCommands.HEARTBEAT_RESPONSE.value:
                        logger.debug('Command complete.')
                    else:
                        logger.error('Unsupported Command')
            else:
                logger.error(
                    f'Node ID does not match the node request was sent to. Node ID: {self._nid}, Node ID from '
                    'vision-agent: {nid}')
        except (SecurityException, XmlException, NodeException, ValueError) as error:
            logger.error('Error parsing/validating manifest: {}'.format(error))
            # If error happened, send the error message back to vision-agent.
            command = SendTelemetryEventCommand(
                self._nid, self.node_callback.get_xlink(), str(error))
            self._invoker.add(command)

    def _process_configuration_command(self, cmd: str, target_type: str, dictionary: Any) -> Optional[Command]:
        if cmd is NodeCommands.get_configuration.value:
            return self._create_configuration_command(
                cmd, dictionary, target_type, GET_ELEMENT)

        if cmd is NodeCommands.set_configuration.value:
            return self._create_configuration_command(
                cmd, dictionary, target_type, SET_ELEMENT)

        if cmd == LOAD:
            logger.debug("config - load")
            node_conf_path = Path(dictionary)
            dictionary = os.path.join(CACHE, node_conf_path.name)
            if target_type == NODE:
                self._validate_key(dictionary)
                return LoadConfigCommand(
                    self._nid, self.node_callback.get_xlink(), self._config, dictionary, target_type)
            elif target_type == NODE_CLIENT:
                if self.file_name:
                    DataHandler.move_file(node_conf_path.name, CACHE, CACHE_MANAGEABILITY)
                    return SendOtaClientConfigurationCommand(
                        self.node_callback.get_broker(), os.path.join(CACHE_MANAGEABILITY,
                                                                      node_conf_path.name), LOAD)

        if cmd is NodeCommands.append_configuration.value:
            logger.debug("config - append")
            if target_type == NODE:
                logger.info('Node does not support configuration append.')
            elif target_type == NODE_CLIENT:
                return SendOtaClientConfigurationCommand(
                    self.node_callback.get_broker(), dictionary, APPEND)

        if cmd is NodeCommands.remove_configuration.value:
            logger.debug("config - remove")
            if target_type == NODE:
                logger.info('Node does not support configuration remove.')
            elif target_type == NODE_CLIENT:
                return SendOtaClientConfigurationCommand(
                    self.node_callback.get_broker(), dictionary, REMOVE)
        return None

    def _process_command(self, cmd: str, revised_manifest: Optional[str],
                         dictionary: Optional[int]) -> Optional[Command]:
        command: Optional[Command] = None
        if cmd is NodeCommands.RESTART.value:
            command = SendManifestCommand(
                self._nid, self.node_callback.get_broker(), revised_manifest)

        if cmd is NodeCommands.REQUEST_TO_DOWNLOAD.value:
            command = RequestToDownloadCommand(
                self._nid, self.node_callback.get_xlink(), dictionary)

        if cmd is NodeCommands.REGISTER_RESPONSE.value:
            if not dictionary:
                raise ValueError("RegisterResponse requires a heartbeat interval setting.")
            self._heartbeat_interval = int(dictionary)
            if self._heartbeat:
                self._heartbeat.stop()

            self._heartbeat = HeartbeatTimer(
                self._heartbeat_interval, self.send_heartbeat)

        if cmd is NodeCommands.HEARTBEAT_RESPONSE.value:
            logger.debug("Receive heartbeat response from vision. Cancel the response timer.")
            if self._heartbeat_response_timer:
                self._heartbeat_response_timer.stop()
                self._heartbeat_response_timer = None

        if cmd is NodeCommands.IS_ALIVE.value:
            command = SendHeartbeatCommand(self._nid, self.node_callback.get_xlink())

        if cmd is NodeCommands.OTA_UPDATE.value:
            command = SendManifestCommand(
                self._nid, self.node_callback.get_broker(), revised_manifest)

        if cmd is NodeCommands.reregister.value:
            command = RegisterCommand(self.node_callback.get_xlink())

        return command

    def _create_configuration_command(self, cmd: str, dictionary,
                                      target_type: str, cmd_type: str) -> Command:
        logger.debug("config - {}".format(cmd))
        if target_type == NODE:
            self._validate_key(dictionary)
            return ConfigValuesCommand(
                self._nid, self.node_callback.get_xlink(), self._config, dictionary, cmd, target_type)

        # NODE_CLIENT
        return SendOtaClientConfigurationCommand(
            self.node_callback.get_broker(), dictionary, cmd_type)

    @staticmethod
    def move_file(file_name: str, file_path: str, destination: str) -> None:
        """Move the file to new location.

           @param file_name : name of file
           @param file_path : original file location
           @param destination : the new location
        """
        old_dir = os.path.join(file_path, file_name)
        new_dir = os.path.join(destination, file_name)
        try:
            if os.path.exists(old_dir):
                shutil.move(old_dir, new_dir)
            else:
                logger.error("Directory '{0}' does not exist.".format(old_dir))
        except OSError as err:
            raise NodeException("Unable to load new configuration file: {}".format(err))

    def register(self) -> None:
        """Add Register_command to invoker when node is being initialized.  In the event that a response is not received
        from the vision-agent in the allotted time, it will retry until the retry limit is hit."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._timer = HeartbeatTimer(self._retry_timer, self.register)
        if self._heartbeat_interval is None:
            if self._retry_limit < self._retry_interval:
                command = RegisterCommand(self.node_callback.get_xlink())
                self._invoker.add(command)
                self._retry_limit += 1
            else:
                self._timer.stop()
                logger.error(
                    'No response from vision-agent .... Please check the IA condition and restart Node-agent')
        else:
            self._timer.stop()

    def _validate_key(self, dictionary: str) -> None:
        """To Check the Key library if valid """
        dictionary_key = dictionary[0] if isinstance(dictionary, list) else dictionary
        logger.debug('Checking dictionary_key = {}'.format(dictionary_key))
        if CACHE == (os.path.dirname(dictionary_key)):
            pass
        elif any(x in dictionary_key for x in KEY_DICTIONARY):
            pass
        else:
            error_msg = "Configuration command: FAILED with Invalid Dictionary Key : {0}".format(
                dictionary_key)
            command = SendConfigResponseCommand(
                self._nid, self.node_callback.get_xlink(), error_msg)
            self._invoker.add(command)
            raise NodeException(error_msg)

    def send_heartbeat(self) -> None:
        """Trigger heartbeat signal based on the heartbeat interval"""
        command = SendHeartbeatCommand(self._nid, self.node_callback.get_xlink())
        self._heartbeat = HeartbeatTimer(self._heartbeat_interval, self.send_heartbeat)
        self._invoker.add(command)
        logger.debug("Start heartbeat response timer.")
        self.start_heartbeat_response_timer()

    def start_heartbeat_response_timer(self) -> None:
        """Start a timer to wait for heartbeat response. If timer expires, it creates a Register Command
        and start the Register sequence again"""
        if self._heartbeat_response_timer:
            self._heartbeat_response_timer.stop()
            self._heartbeat_response_timer = None
        self._heartbeat_response_timer = HeartbeatTimer(self._heartbeat_response, self.register)

    def reset_heartbeat(self) -> None:
        """Cancel current heartbeat timer and reset the value"""
        if self._heartbeat is not None:
            self._heartbeat.stop()
        if self._timer is not None:
            self._timer.stop()
        self._heartbeat_interval = None
        self._retry_limit = 0

    def downloaded_file(self, file_name, receive_status: bool) -> None:
        """Add Send_Download_Status_Name command into invoker if the OTA file exists
        @param file_name: relative filename from CACHE
        @param receive_status : File receive status
        """
        self.file_name = file_name
        if receive_status is True:
            receive_status = os.path.isfile(os.path.join(CACHE, file_name))
            logger.info('File %s Transfer status: %s',
                        file_name, receive_status)

        command = SendDownloadStatusCommand(
            self._nid, self.node_callback.get_xlink(), receive_status)
        self._invoker.add(command)

    def publish_config_value(self, children: Optional[dict]) -> None:
        """Update new value after load element
        @param children: element and value
        """
        if children:
            for child in children:
                value = children[child]
                if child == REGISTRATION_RETRY_TIMER_SECS:
                    self._retry_timer = configuration_bounds_check(
                        CONFIG_REGISTRATION_RETRY_TIMER_SECS, int(value))
                if child == REGISTRATION_RETRY_LIMIT:
                    self._retry_interval = configuration_bounds_check(
                        CONFIG_REGISTRATION_RETRY_LIMIT, int(value))
                if child == HEARTBEAT_RESPONSE_TIMER_SECS:
                    self._heartbeat_response = \
                        configuration_bounds_check(
                            CONFIG_HEARTBEAT_RESPONSE_TIMER_SECS, int(value))
        else:
            logger.error('Children value is empty')

    def stop(self) -> None:
        """Stop the invoker and heartbeat checking timer"""
        if self._timer is not None:
            self._timer.stop()
        if self._invoker is not None:
            self._invoker.stop()
        if self._heartbeat is not None:
            self._heartbeat.stop()
