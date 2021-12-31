"""
    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from datetime import datetime
from typing import Dict, Any
from typing import Optional, Tuple

from .command.command import VisionCommands
from .constant import VisionException

from inbm_vision_lib.constants import ERROR_UNINITIALIZED_OBJECT, XmlException
from inbm_vision_lib.xml_handler import XmlHandler

logger = logging.getLogger(__name__)


class XLinkParser(object):
    """Concrete class to process the Command manifest received from xlink"""

    def __init__(self) -> None:
        super().__init__()
        self._xml_handler: Optional[XmlHandler] = None
        self.command_type = None

    def parse(self, manifest: str) -> Tuple[Any, Any, Dict[str, Any]]:
        """Parses the OTA manifest received from the OTA client. Grab the information and store
        them in dictionary format.

        @param manifest: OTA manifest receiving from OTA client
        @return: (str, str, dict) The type of Command, node id, Command info stored in
        dictionary format
        """

        logger.debug("Start parsing the manifest.")
        try:
            self._xml_handler = XmlHandler(xml=manifest)
        except XmlException as error:
            raise XmlException(error)

        header, self.command_type = self._check_command_type()
        if self.command_type is None:
            raise ValueError('Command unsupported.')

        node_id = self._check_node_id()
        if node_id is None:
            raise ValueError('Node id not found.')

        dictionary = None
        if self.command_type is VisionCommands.REGISTER.value:
            dictionary = self._parse_node_registration()
        if self.command_type is VisionCommands.HEARTBEAT.value:
            dictionary = None
        if self.command_type is VisionCommands.DOWNLOAD_STATUS.value:
            dictionary = self._parse_download_status()
        if self.command_type is VisionCommands.SEND_FILE_RESPONSE.value:
            dictionary = self._parse_send_file_response()
        if self.command_type is VisionCommands.OTA_RESULT.value:
            dictionary = self._parse_ota_result()
        if self.command_type is VisionCommands.TELEMETRY_EVENT.value:
            dictionary = self._parse_telemetry_event()
        if self.command_type is VisionCommands.CONFIG_RESPONSE.value:
            dictionary = self._parse_config_response()

        logger.debug("Parser done.")
        return self.command_type, node_id, dictionary

    def _check_command_type(self) -> Tuple[Any, Any]:
        """Checks the type of Command object

        @return: (dict, str) The header of manifest, the type of Command
        """
        for command_type in VisionCommands:
            if self._xml_handler is None:
                raise VisionException(ERROR_UNINITIALIZED_OBJECT)
            header = self._xml_handler.get_children(command_type.value)
            if header is not None:
                logger.info("Command type: %s", command_type.value)
                return header, command_type.value
        return None, None

    def _check_node_id(self):
        """Method to check the type of Command

        @return: Node device id
        """

        try:
            if self._xml_handler is None:
                raise VisionException(ERROR_UNINITIALIZED_OBJECT)
            node_id = self._xml_handler.get_attribute(self.command_type, "id")
            if node_id is not None:
                logger.info("Node id: %s", str(node_id))
                return node_id
        except KeyError:
            return None

    @staticmethod
    def _is_valid_node_registration(info: str, register_items: dict) -> bool:
        """Method to validate node registration information.

        @param info: (str) information to be registered
        @param register_items: (dict) node information stored in dict
        @return: (bool) True if it passed the validation
        """
        if info == "bootFwDate" and register_items["bootFwDate"] is None:
            return False
        if info == "bootFwVersion" and register_items["bootFwVersion"] is None:
            return False
        if info == "bootFwVendor" and register_items["bootFwVendor"] is None:
            return False

        return True

    @staticmethod
    def create_date_time_from_string(date_str: str, fmt: str) -> Optional[datetime]:
        """Method to create datetime object from string. 

        @param date_str: string representing date
        @param fmt: datetime format
        @return: datetime object
        """
        if date_str == 'None':
            return None

        date = date_str.split("-")
        if date[0] == "" or date[1] == "" or date[2] == "":
            return None

        return datetime.strptime(date_str, fmt)

    def _parse_node_registration(self) -> Dict[str, Any]:
        """Method to parse node registration Command

        @return: the info of node agent
        """

        if self._xml_handler is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)

        register_items = self._xml_handler.get_children(self.command_type + '/items')
        node_info: Dict[str, Any] = {"bootFwDate": None,
                                     "bootFwVendor": None,
                                     "bootFwVersion": None,
                                     "osType": None,
                                     "osVersion": None,
                                     "osReleaseDate": None,
                                     "manufacturer": None,
                                     "dmVerityEnabled": None,
                                     "measuredBootEnabled": None,
                                     "flashless": None,
                                     "is_xlink_secure": None,
                                     "stepping": None,
                                     "sku": None,
                                     "model": None,
                                     "product": None,
                                     "serialNumber": None,
                                     "version": None}

        for info in node_info:
            if XLinkParser._is_valid_node_registration(info, register_items):
                try:
                    if info == "bootFwDate":
                        try:
                            fw_date = XLinkParser.create_date_time_from_string(
                                register_items[info], "%m-%d-%Y")
                            if not fw_date:
                                raise XmlException("bootFwDate date is empty.")
                            node_info[info] = fw_date
                        except (XmlException, IndexError) as error:
                            raise XmlException(error)
                    elif info == "flashless" or info == "is_xlink_secure":
                        node_info[info] = register_items[info] == "True"
                    elif info == "osReleaseDate":
                        try:
                            os_date = XLinkParser.create_date_time_from_string(
                                register_items[info], "%m-%d-%Y-%H-%M-%S")
                        except ValueError:
                            # In older version of node, it doesn't send hour, minute and seconds
                            os_date = XLinkParser.create_date_time_from_string(
                                register_items[info], "%m-%d-%Y")
                        node_info[info] = os_date
                    else:
                        node_info[info] = register_items[info]
                except (KeyError, ValueError):
                    node_info[info] = None
            else:
                raise XmlException("{0} is empty.".format(info))

        logger.info("Node registration information: " + str(node_info))
        return node_info

    def _parse_download_status(self) -> Dict[str, Any]:
        """Parses download status response from node

        @return: (dict) status of download
        """

        if self._xml_handler is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)

        download_status_items = self._xml_handler.get_children(self.command_type + '/items')
        download_status = {"status": download_status_items["status"]}
        logger.info("Download status: " + str(download_status["status"]))
        return download_status

    def _parse_send_file_response(self) -> Dict[str, Any]:
        """Parses send file response from node

        @return: (dict) status to send the file to node
        """

        if self._xml_handler is None:
            raise VisionException("Uninitialized object")
        if self.command_type is None:
            raise VisionException("Uninitialized object")

        send_file_response_items = self._xml_handler.get_children(self.command_type + '/items')
        send_download_status = {"sendDownload": send_file_response_items["sendDownload"]}
        logger.info("sendDownload status: " + str(send_download_status["sendDownload"]))
        return send_download_status

    def _parse_ota_result(self) -> Dict[str, Any]:
        """parses OTA result received from node

        @return: (dict) status of OTA update
        """

        if self._xml_handler is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)

        ota_result_items = self._xml_handler.get_children(self.command_type + '/items')
        ota_result_status = {"result": ota_result_items["result"]}
        logger.info("otaResult: " + str(ota_result_status["result"]))
        return ota_result_status

    def _parse_telemetry_event(self) -> Dict[str, Any]:
        """Parses telemetry event message received from the OTA client.

        @return: (dict) the telemetry message
        """

        if self._xml_handler is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)

        telemetry_event_items = self._xml_handler.get_children(self.command_type + '/items')

        telemetry_event_message = {"telemetryMessage": telemetry_event_items["telemetryMessage"]}
        logger.info("telemetryMessage: " + str(telemetry_event_message["telemetryMessage"]))
        return telemetry_event_message

    def _parse_config_response(self) -> Dict[str, Any]:
        """Parses config response received from xlink.

        @return: (dict) the config response message
        """

        if self._xml_handler is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)
        if self.command_type is None:
            raise VisionException(ERROR_UNINITIALIZED_OBJECT)

        config_response_items = self._xml_handler.get_children(self.command_type + '/items')

        config_response_message = {"item": config_response_items["configMessage"]}
        logger.info("configResponseMessage: " + str(config_response_message["item"]))
        return config_response_message
