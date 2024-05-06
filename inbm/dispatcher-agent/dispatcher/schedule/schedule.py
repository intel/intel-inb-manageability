"""
    Schedule a task for later execution

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Any, Tuple
from inbm_lib.xmlhandler import XmlException

def schedule_update(xpath: str, parsed_xml: Any) -> Tuple[bool, str]:
    """Schedule a task for later execution

    @param xpath: xpath to check if scheduled
    @param parsed_xml: parsed XML
    @return: Tuple of (taskScheduled, message)
    """
    is_scheduled_task = parsed_xml.is_element_exist(xpath)
    if is_scheduled_task:
        try:
            parsed_xml.remove_element(xpath)
        except XmlException as e:
            raise XmlException(f"Error removing scheduledTime element.  Unable to schedule task.: {e}")
        #TODO: Add schedule to DB
        return True, "Task Scheduled"
    return False, ""
