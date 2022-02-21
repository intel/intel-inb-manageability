"""
    Different command object will be created according to different request.
    Each concrete classes have different execute method for different purpose.

    @copyright: Copyright 2021 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""

import logging
from typing import Optional, List

from .command import Command
from ..broker import Broker
from ..registry_manager import RegistryManager
from ..node_communicator.node_connector import NodeConnector
from ..constant import VISION_ID, NO_ACTIVE_NODES_FOUND_ERROR, VisionException

from inbm_common_lib.utility import clean_input, remove_file

from inbm_vision_lib.constants import CONFIG_GET, CONFIG_SET, CONFIG_APPEND, CONFIG_REMOVE, create_error_message, \
    create_success_message
from inbm_vision_lib.configuration_manager import ConfigurationManager, ConfigurationException


logger = logging.getLogger(__name__)


class GetVisionConfigValuesCommand(Command):
    """Get values from the vision-agent configuration file.

    @param nid: id of the node
    @param broker: instance of Broker object
    @param key: key to fetch the value from the conf file
    @param config_mgr: instance of Configuration Manager
    @param target_type: target of the configuration request [vision, node, node_client]
    """

    def __init__(self, nid: str, broker: Optional[Broker], key: List[str], config_mgr: ConfigurationManager,
                 target_type: Optional[str]) -> None:
        super().__init__(nid)
        self.broker = broker
        self.key = key
        self.nid = nid
        self.config_mgr = config_mgr
        self.target_type = target_type

    def execute(self) -> None:
        """Get config value through configurationManager and publish the result to telemetryEvent"""
        logger.debug('Execute GetVisionConfigValuesCommand.')
        try:
            result = self.config_mgr.get_element(self.key, self.target_type)
            for num in range(len(self.key)):
                message = "{0}/{1}:{2}".format(self.target_type, self.key[num], result[num])
                if self.broker:
                    self.broker.publish_telemetry_event(self.nid, message)
                    resp_msg = create_success_message("Configuration command: SUCCESSFUL")
                    self.broker.publish_telemetry_response(self.nid, resp_msg)
        except(ConfigurationException, AttributeError, KeyError):
            if self.broker:
                err_resp = create_error_message("Configuration command: FAILED")
                self.broker.publish_telemetry_response(self.nid, err_resp)


class SetVisionConfigValuesCommand(Command):
    """Set values from the vision-agent configuration file.

    @param nid: id of the node
    @param broker: instance of Broker object
    @param key: key to fetch the value from the conf file
    @param config_mgr: instance of Configuration Manager
    @param target_type: target of the configuration request [vision, node, node_client]
    """

    def __init__(self, nid: str, broker: Optional[Broker], key: List[str], config_mgr: ConfigurationManager,
                 target_type: Optional[str]) -> None:
        super().__init__(nid)
        self.broker = broker
        self.key = key
        self.nid = nid
        self.config_mgr = config_mgr
        self.target_type = target_type

    def execute(self) -> None:
        """Execute set config and publish the result to telemetry Event"""
        logger.debug('Execute SetVisionConfigValuesCommand.')
        try:
            result = self.config_mgr.set_element(self.key, self.target_type)
            for num in range(len(self.key)):
                message = "{0}/{1}:{2}".format(self.target_type,
                                               clean_input
                                               (self.key[num]), result[num])
                if self.broker:
                    self.broker.data_handler.manage_configuration_update(self.key[num])
                    self.broker.publish_telemetry_event(self.nid, message)
                    success_resp = create_success_message("Configuration command: SUCCESSFUL")
                    self.broker.publish_telemetry_response(self.nid, success_resp)
        except (ConfigurationException, ValueError, KeyError) as error:
            message = "Error on Set Element.{}".format(error)
            if self.broker:
                self.broker.publish_telemetry_event(self.nid, message)
                err_resp = create_error_message("Configuration command: FAILED")
                self.broker.publish_telemetry_response(self.nid, err_resp)


class SendNodeConfigValueCommand(Command):
    """Send configuration request to node agent via xlink.

    @param node_connector: instance of NodeConnector
    @param register_mgr: instance of RegistryManager object
    @param keys: key to fetch the value from the node conf file
    @param config_cmd_type: string represents configuration request type
    @param targets: target nodes to be configured
    @param target_type: string representing target type
    """

    def __init__(self, node_connector: Optional[NodeConnector], register_mgr: RegistryManager,
                 keys: List[str], config_cmd_type: str, targets: List[str], target_type: str) -> None:
        super().__init__(VISION_ID)
        self.node_connector = node_connector
        self.register_mgr = register_mgr
        self.keys = keys
        self.config_type = config_cmd_type
        self.target_node = targets
        self.target_type = target_type

    def _get_manifest_type(self) -> str:  # type: ignore
        """
        @return: str manifest_type
        """
        if self.config_type == CONFIG_GET:
            return "getConfigValues"
        if self.config_type == CONFIG_SET:
            return "setConfigValues"
        if self.config_type == CONFIG_APPEND:
            return "appendConfigValues"
        if self.config_type == CONFIG_REMOVE:
            return "removeConfigValues"

    def execute(self) -> None:
        """Publish the config request to node-agent through xlink."""
        logger.debug('Execute SendNodeConfigValueCommand.')
        # Remove empty key
        key_list = [key for key in self.keys if key]
        target_type = '        <targetType>{}</targetType>'.format(clean_input(self.target_type))
        items = ''
        for key in key_list:
            key = key
            items = items + '            <key>{}</key>'.format(clean_input(key))

        # Get a list of active node from targets. If targets is None, send request to all node.
        targeted_node = self.register_mgr.get_target_ids(self.target_node)
        logger.debug("targeted_node: {}".format(targeted_node))
        if not targeted_node:
            raise VisionException(NO_ACTIVE_NODES_FOUND_ERROR + "Config update failed.")

        manifest_type = self._get_manifest_type()

        for nid in targeted_node:
            revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                                '<message>' +
                                '    <{0} id="{1}">' +
                                '{2}' +
                                '        <items>' +
                                '{3}' +
                                '        </items>' +
                                '    </{0}>' +
                                '</message>'
                                ).format(
                manifest_type,
                nid,
                target_type,
                items
            )
            logger.debug("Revised Manifest: {}".format(revised_manifest))
            if self.node_connector:
                self.node_connector.send(revised_manifest, nid)
            else:
                raise VisionException("Failed to send message to nodes")


class LoadConfigFileCommand(Command):
    """Send load config request to the configuration manager to load the values.

    @param nid: id of the node
    @param broker: instance of Broker object
    @param path: (str) location of the new config file
    @param config_mgr: instance of Configuration Manager
    @param config_cmd_type: string represents configuration request type
    """

    def __init__(self, nid: str, broker: Optional[Broker], path: str, config_mgr: ConfigurationManager,
                 config_cmd_type: str) -> None:
        super().__init__(nid)
        self.broker = broker
        self.path = path
        self.config_mgr = config_mgr
        self.config_type = config_cmd_type

    def execute(self) -> None:
        """Load the new configuration file"""
        logger.debug('Execute LoadConfigFileCommand.')
        try:
            self.config_mgr.load(self.path)
            if self.broker:
                self.broker.data_handler.load_config_file()
        except ConfigurationException as error:
            error_msg = create_error_message("Configuration command: FAILED " + str(error))
            if self.broker:
                self.broker.publish_telemetry_response(self._nid, error_msg)
        finally:
            remove_file(self.path)


class SendNodeConfigurationLoadManifestCommand(Command):

    """SendNodeConfigurationLoadManifestCommand Concrete class

    @param nid: id of node that sent response
    @param node_connector: instance of NodeConnector
    @param manifest: OTA manifest sent to nodes via Xlink
    @param target_type: target type of the load config request, either node or node_client
    """

    def __init__(self, nid: str, node_connector: Optional[NodeConnector], manifest: str, target_type: str) -> None:
        super().__init__(nid)
        self.node_connector = node_connector
        self.manifest = manifest
        self.target_type = target_type

    def execute(self) -> None:
        """Send revised OTA manifest to node through xlink manager"""
        logger.debug('Execute SendNodeConfigurationLoadManifestCommand.')
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '<message>'
                            '    <configRequest id="{0}">'
                            '        <items>'
                            '            <manifest>'
                            '                <type>config</type>'
                            '                <config>'
                            '                    <cmd>load</cmd>'
                            '                    <targetType>{1}</targetType>'
                            '                    <configtype>'
                            '                        <load>'
                            '                {2}'
                            '                        </load>'
                            '                    </configtype>'
                            '                </config>'
                            '            </manifest>'
                            '        </items>'
                            '    </configRequest>'
                            '</message>'
                            ).format(
            self._nid,
            clean_input(self.target_type),
            self.manifest
        )
        if self.node_connector:
            self.node_connector.send(revised_manifest, self._nid)
