"""
    Schedule a task for later execution

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Any, Tuple
from inbm_lib.xmlhandler import XmlException
from .sqlite_manager import SqliteManager
from .scheduled_task import ScheduledTask
from ..constants import UDM_DB_FILE

logger = logging.getLogger(__name__)
       
def schedule_update(parsed_xml: Any) -> Tuple[bool, str]:
    """Schedule a task for later execution

    @param xml: manifest to be processed
    """
    logger.debug(f"Received schedule request: {parsed_xml}")
    # TODO: Add more checking, multiple singleSchedule support, add multiple tasks, implement repeatedSchedule
    if parsed_xml.get_element_text('schedule/singleSchedule'):
        task = ScheduledTask(start_time=parsed_xml.get_element_text('schedule/singleSchedule/start_time'),
                             end_time=parsed_xml.get_element_text('schedule/singleSchedule/end_time'),
                             manifest=parsed_xml)
        SqliteManager(UDM_DB_FILE).create_task(task)
        return True, "Task Scheduled"
    return False, "Unsupported schedule request."