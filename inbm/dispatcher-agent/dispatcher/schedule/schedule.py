"""
    Schedule a task for later execution

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Any, Tuple
from inbm_lib.xmlhandler import XmlException
from .sqlite_manager import SqliteManager
from inbm_lib.constants import SQL_DATA_FILE

logger = logging.getLogger(__name__)

def schedule_update(xpath: str, parsed_xml: Any) -> Tuple[bool, str]:
    """Schedule a task for later execution

    @param xpath: xpath to check if scheduled
    @param parsed_xml: parsed XML
    @return: Tuple of (taskScheduled, message)
    """
    is_scheduled_task = parsed_xml.is_element_exist(xpath)
    logger.debug(f"Is scheduledTime Exist = {is_scheduled_task}")
    if is_scheduled_task:
        try:
            parsed_xml.remove_element(xpath)
        except XmlException as e:
            raise XmlException(f"Error removing scheduledTime element.  Unable to schedule task.: {e}")
        #TODO: Add schedule to DB
        return True, "Task Scheduled"
    else:
        return False, "Element not found."
