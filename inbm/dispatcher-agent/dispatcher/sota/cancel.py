"""
    Method to handle cancel request

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import signal
from inbm_lib.xmlhandler import XmlHandler
from threading import Thread
from .constants import SOTA_CACHE
from ..constants import OtaType
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.local_repo import DirectoryRepo

logger = logging.getLogger(__name__)


def cancel_thread(type_of_manifest: str, parsed_head: XmlHandler, thread_list: list[Thread]) -> bool:
    """
    Cancel the current active thread by sending the terminate signal.

    @param type_of_manifest: type of the request
    @param parsed_head: The root parsed xml
    @param thread_list: List of the active thread
    @return: True if the request has been processed; False if no request has been handled.
    """

    if type_of_manifest == 'ota':
        header = parsed_head.get_children('ota/header')
        ota_type = header['type']
        resource = parsed_head.get_children(f'ota/type/{ota_type}')
        if ota_type == OtaType.SOTA.name.lower():
            sota_mode = resource.get('mode', None)
            if sota_mode == 'cancel':
                logger.debug(f"Receive sota cancel request.")
                # The list should only contain one OTA process.
                for thread in thread_list:
                    if thread.is_alive() and thread.ident:
                        logger.debug(f"Terminate thread={thread.ident}.")
                        signal.pthread_kill(thread.ident, signal.SIGTERM)
                        # Remove the repo after killing the thread
                        try:
                            sota_cache_repo = DirectoryRepo(SOTA_CACHE)
                            sota_cache_repo.delete_all()
                        except DispatcherException as e:
                            # If the directory doesn't exist, print the error.
                            logger.error(e)
                return True
    return False
