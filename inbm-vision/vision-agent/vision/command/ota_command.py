"""
    Different command object will be created according to different request.
    Each concrete classes have different execute method for different purpose.

    Copyright (C) 2017-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from typing import Optional, Dict

from inbm_common_lib.utility import clean_input

from .command import Command

from ..node_communicator.node_connector import NodeConnector
from ..constant import VISION_ID
from ..updater import Updater


logger = logging.getLogger(__name__)


class ReceiveRequestDownloadResponse(Command):

    """ReceiveRequestDownloadResponse Concrete class

    @param nid: id of node that sent response
    @param updater: instance of Updater object
    @param response: True/False response from node
    """

    def __init__(self, nid: str, updater, response: Dict[str, str]) -> None:
        super().__init__(nid)
        self.response = response["sendDownload"]
        self.updater = updater

    def execute(self) -> None:
        """Call Updater API to update the download request status based on node's response"""
        logger.debug('Execute ReceiveRequestDownloadResponse.')
        if self.response == "True":
            self.updater.update_download_request_status(self._nid, True)
        else:
            self.updater.update_download_request_status(self._nid, False)


class ReceiveDownloadResponseCommand(Command):

    """ReceiveDownloadResponseCommand Concrete class

    @param nid: id of node that sent response
    @param updater: instance of Updater object
    @param response: True/False response from node
    """

    def __init__(self, nid: str, updater, response: Dict[str, str]) -> None:
        super().__init__(nid)
        self.response = response["status"]
        self.updater = updater

    def execute(self) -> None:
        """Call Updater API to update the download status based on node's response"""
        logger.debug('Execute ReceiveDownloadResponseCommand.')
        if self.response == "True":
            self.updater.update_download_status(self._nid, True)
        else:
            self.updater.update_download_status(self._nid, False)


class SendFileCommand(Command):

    """SendFileCommand Concrete class

    @param nid: id of node that sent response
    @param node_connector: instance of NodeConnector
    @param file_path: location of file being send to nodes via Xlink
    """

    def __init__(self, nid: str, node_connector: Optional[NodeConnector], file_path: str) -> None:
        super().__init__(nid)
        self.node_connector = node_connector
        self.file_path = file_path

    def execute(self) -> None:
        """Send OTA file with file name to node"""
        logger.debug('Execute SendFileCommand.')
        if self.node_connector:
            self.node_connector.send_file(self._nid, clean_input(self.file_path))


class UpdateNodeCommand(Command):

    """UpdateNodeCommand Concrete class
    @param updater: Updater instance
    """

    def __init__(self, updater: Updater) -> None:
        super().__init__(VISION_ID)
        self.updater = updater

    def execute(self) -> None:
        """Call updater API to send the request to send file to node"""
        logger.debug('Execute UpdateNodeCommand.')
        self.updater.send_request_to_send_file()
