"""
    Interface to DataHandler class

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from abc import ABC, abstractmethod
from typing import Union, Dict


class IDataHandler(ABC):
    """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
    to the command objects and which commands it assigns to the invoker."""

    @abstractmethod
    def receive_restart_request(self, payload: str) -> None:
        """Receive request from OTA client to restart node(s).
        - Parse the manifest
        - Create timer and trigger restart for each target

        @param payload: manifest received from OTA client
        """

        pass

    @abstractmethod
    def receive_mqtt_message(self, payload: str) -> None:
        """Receive OTA update manifest from OTA client and trigger an OTA update.
        - Parse the manifest
        - Create updater timer and start OTA update for each target

        @param payload: manifest received from OTA client
        """

        pass

    @abstractmethod
    def manage_configuration_request(self, message: str) -> None:
        """Manage the configuration request payload:
        @param message: config request message
        """
        pass

    @abstractmethod
    def manage_configuration_update(self, key: str) -> None:
        """Manage the configuration request to update the vision-agent:
        @param key: configuration setting to be updated
        """

        pass

    @abstractmethod
    def receive_xlink_message(self, message) -> None:
        """Receive the message from xlink. It has following flows:

        1. Parse the xml received from node
        2. Determine which command it is
        3. Create the correct Command object
        4. Add the Command to Invoker

        @param message: message received from xlink
        """

        pass

    @abstractmethod
    def send_node_register_response(self, node_id: str) -> None:
        """Create registration confirmation command with heartbeat interval(s) to node

        @param node_id: device ID of the targeted node
        """

        pass

    @abstractmethod
    def send_heartbeat_response(self, node_id) -> None:
        """Send heartbeat response message to node after receiving a heartbeat message

        @param node_id: a string contains device id of targeted node agent
        """

        pass

    @abstractmethod
    def create_telemetry_event(self, node_id: str, message: str) -> None:
        """Create send telemetry event command that will send the message through broker

        @param node_id: device ID of the targeted node
        @param message: message to be sent via broker
        """

        pass

    @abstractmethod
    def send_is_alive(self, node_id: str) -> None:
        """Send isAlive request command to node when node doesn't response for a long time

        @param node_id: device ID of the targeted node
        """

        pass

    @abstractmethod
    def send_reregister_request(self, node_id: str) -> None:
        """Create send reregister request command and send to node

        @param node_id: device ID of the targeted node
        """

        pass

    @abstractmethod
    def create_download_request(self, node_id: str, file_size: int) -> None:
        """Create send download request command with file size to be sent to node

        @param node_id: device ID of the targeted node
        @param file_size: file size in KB
        """

        pass

    @abstractmethod
    def send_file(self, node_id: str, file_path: str) -> None:
        """Create send ota file command with filename to node

        @param node_id: device ID of the targeted node
        @param file_path: a string contains location of file to be sent
        """

        pass

    @abstractmethod
    def send_telemetry_response(self, node_id: str, message: Dict[str, str]) -> None:
        """Create send telemetry response command that will send the message through broker

        @param node_id: device ID of the targeted node
        @param message: message to be sent via broker
        """

        pass

    @abstractmethod
    def send_ota_manifest(self, node_id: str, manifest: str) -> None:
        """Create send ota manifest command with revised manifest to node

        @param node_id: device ID of the targeted node
        @param manifest: a revised manifest to be sent to node
        """

        pass

    @abstractmethod
    def send_config_load_manifest(self, node_id: str, manifest: str, target_type: str) -> None:
        """Create send node configuration load manifest command with revised manifest to node

        @param node_id: device ID of the targeted node
        @param manifest: a revised manifest to be sent to node
        @param target_type: target type of the load config request, either node or node_client
        """

        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the invoker and heartbeat checking timer"""

        pass

    @abstractmethod
    def load_config_file(self, startup: bool = False) -> None:
        """Load the config value from config file.

        @param startup: if called as part of startup of DataHandler
        """

        pass

    @abstractmethod
    def receive_command_request(self, message: str) -> None:
        """Handle the query request sent by client

        @param message: payload received
        """

        pass

    @abstractmethod
    def publish_xlink_status(self, nid: str, status: str) -> None:
        """Pass xlink status to broker and publish to subscriber.

        @param nid: Node ID
        @param status: xlink device status message
        """

        pass

    @abstractmethod
    def reset_device(self, node_id: str) -> None:
        """Reset device when the device is no longer active.

        @param node_id: node to be reset
        """
        pass
