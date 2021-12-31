""""
    Class for creating Command object for configuration request

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Optional, List

from inbm_vision_lib.configuration_manager import ConfigurationManager, ConfigurationException

from inbm_common_lib.utility import clean_input, remove_file

from ..node_exception import NodeException
from ..xlink_manager import XlinkManager

from .command import Command, NodeCommands


logger = logging.getLogger(__name__)


class SendConfigResponseCommand(Command):
    """SendConfigResponseCommand Concrete class

    @param nid: id of node that sent response
    @param xlink_manager: Node Xlink Manager
    @param message: config response to send back to vision-agent via xlink
    """

    def __init__(self, nid: Optional[str], xlink_manager: Optional[XlinkManager], message: str) -> None:
        super(SendConfigResponseCommand, self).__init__(nid)
        self.xlink_manager = xlink_manager
        self.message = message

    def execute(self) -> None:
        """Send telemetry event message through xlink"""
        manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                    '<message>' +
                    '    <configResponse id="{0}">' +
                    '        <items>' +
                    '            <configMessage>{1}</configMessage>' +
                    '        </items>' +
                    '    </configResponse>' +
                    '</message>').format(self._nid, self.message)
        if self.xlink_manager:
            self.xlink_manager.send(manifest)
        else:
            raise NodeException("Failed to send message via XLink")


class ConfigValuesCommand(Command):
    """Call broker to publish get_config payload.

       @param nid : id of the node
       @param xlink_manager : Node Xlink Manager
       @param config_mngr : Configuration Manager
       @param key: key to fetch the value from the conf file
       @param cmd: issued command: Get, Set
       @param target_type: Target for command: node, node_client
    """

    def __init__(self, nid: Optional[str], xlink_manager: Optional[XlinkManager],
                 config_mngr: ConfigurationManager, key: List[str], cmd: str, target_type: str) -> None:
        """Init GetConfigValuesCommand."""
        super().__init__(nid)
        self.xlink_manager = xlink_manager
        self.config_mngr = config_mngr
        self.key = key
        self.cmd = cmd
        self.target_type = target_type
        self.resp_msg = "Configuration command: "

    def execute(self):
        try:
            if self.cmd is NodeCommands.get_configuration.value:
                result = self.config_mngr.get_element(self.key, self.target_type)
            elif self.cmd is NodeCommands.set_configuration.value:
                result = self.config_mngr.set_element(self.key, self.target_type)
                if self.xlink_manager:
                    children = self.config_mngr.get_children(self.target_type)
                    self.xlink_manager.node_data_handler.publish_config_value(children)
            else:
                raise NodeException("Invalid command received: {}".format(self.cmd))

            for num in range(len(self.key)):
                key = clean_input(self.key[num])
                value = result[num]
                self.resp_msg = self.resp_msg + "SUCCESSFUL"
                manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                            '<message>' +
                            '    <configResponse id="{0}">' +
                            '        <items>' +
                            '            <configMessage>{1} {2}:{3}</configMessage>' +
                            '        </items>' +
                            '    </configResponse>' +
                            '</message>').format(self._nid, self.resp_msg, key, value)

                if self.xlink_manager:
                    logger.debug("Manifest: {}".format(manifest))
                    self.xlink_manager.send(manifest)
                else:
                    raise NodeException("Failed to send message via XLink")

        except (ConfigurationException, ValueError, KeyError, AttributeError) as error:
            logger.error('Error parsing/validating manifest: {}'.format(error))
            self.resp_msg = self.resp_msg + "FAILED "
            manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                        '<message>' +
                        '    <configResponse id="{0}">' +
                        '        <items>' +
                        '            <configMessage>{1}, failed with error:{2}</configMessage>' +
                        '        </items>' +
                        '    </configResponse>' +
                        '</message>').format(self._nid, self.resp_msg, error)

            if self.xlink_manager:
                logger.debug("Manifest: {}".format(manifest))
                self.xlink_manager.send(manifest)
            else:
                raise NodeException("Failed to send message via XLink")


class LoadConfigCommand(Command):
    """Call broker to publish get_config payload.

       @param nid : id of the node
       @param xlink_manager : Node Xlink Manager
       @param config_mngr : Configuration Manager
       @param path: path to fetch the value from the conf file
    """

    def __init__(self, nid: Optional[str], xlink_manager: Optional[XlinkManager],
                 config_mgr: ConfigurationManager, path: str, target_type: str) -> None:
        """Init GetConfigValuesCommand."""
        super().__init__(nid)
        self.xlink_manager = xlink_manager
        self.config_mgr = config_mgr
        self.path = path
        self.target_type = target_type

    def execute(self):
        try:
            self.config_mgr.load(self.path)
            children = self.config_mgr.get_children(self.target_type)
            if self.xlink_manager:
                self.xlink_manager.node_data_handler.publish_config_value(children)
            message = {'status': '200', 'message': 'NODE Configuration command: SUCCESSFUL'}
        except (ConfigurationException, ValueError, KeyError) as error:
            message = {'status': '400', 'message': 'Configuration command: FAILED'}
            logger.error('Error : {}'.format(error))
        finally:
            remove_file(self.path)

        manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                    '<message>' +
                    '    <configResponse id="{0}">' +
                    '        <items>' +
                    '            <configMessage> :{1}</configMessage>' +
                    '        </items>' +
                    '    </configResponse>' +
                    '</message>').format(self._nid, message)

        if self.xlink_manager:
            logger.debug("Manifest: {}".format(manifest))
            self.xlink_manager.send(manifest)
        else:
            raise NodeException("Failed to send message via XLink")
