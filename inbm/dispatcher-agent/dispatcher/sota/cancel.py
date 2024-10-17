"""
    Method to handle cancel request

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Optional
from threading import Event
from inbm_lib.xmlhandler import XmlHandler
from threading import Thread
from .constants import SOTA_CACHE
from ..constants import OtaType
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.dispatcher_broker import DispatcherBroker
from dispatcher.common.result_constants import Result, CODE_OK, CODE_BAD_REQUEST

logger = logging.getLogger(__name__)


def cancel_thread(type_of_manifest: str, parsed_head: XmlHandler, thread_list: list[Thread],
                  type_of_active_manifest: Optional[str], active_thread_parsed_head: Optional[XmlHandler],
                  dispatcher_broker: DispatcherBroker, cancel_event: Event) -> bool:
    """
    Cancel the current active thread by sending the terminate signal.

    @param type_of_manifest: type of the request
    @param parsed_head: The root parsed xml
    @param thread_list: List of the active thread
    @param type_of_active_manifest: type of the request on running thread
    @param active_thread_parsed_head: The root parsed xml of running thread
    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param cancel_event: Event used to stop the downloading process
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
                # If the active thread is not SOTA download-only, forbid the cancel request.
                if type_of_active_manifest and active_thread_parsed_head:
                    if not is_active_ota_sota_download_only(type_of_active_manifest, active_thread_parsed_head):
                        dispatcher_broker.send_result(
                            str(Result(CODE_BAD_REQUEST, "Current thread is not SOTA download-only. "
                                                         "Cannot proceed with the cancel request.")))
                        return True
                else:
                    dispatcher_broker.send_result(str(Result(CODE_BAD_REQUEST, "Running thread manifest not found.")))
                    return True

                # The list should only contain one OTA process.
                for thread in thread_list:
                    if thread.is_alive():
                        cancel_event.set()
                        # Wait thread to gracefully exit
                        logger.debug(f"Waiting thread to exit...")
                        thread.join(timeout=300)
                        logger.debug(f"Request cancel complete.")
                        # Reset the event flag
                        cancel_event.clear()
                return True
    return False


def is_active_ota_sota_download_only(type_of_active_manifest: str, active_parsed_head: XmlHandler) -> bool:
    """
    Check whether the current active thread is SOTA download-only mode.

    @param type_of_active_manifest: type of the request
    @param active_parsed_head: The root parsed xml
    @return: True if it is SOTA download-only; False if not.
    """
    logger.debug("")
    if type_of_active_manifest == 'ota':
        header = active_parsed_head.get_children('ota/header')
        ota_type = header['type']
        resource = active_parsed_head.get_children(f'ota/type/{ota_type}')
        if ota_type == OtaType.SOTA.name.lower():
            sota_mode = resource.get('mode', None)
            if sota_mode == 'download-only':
                return True
    return False
