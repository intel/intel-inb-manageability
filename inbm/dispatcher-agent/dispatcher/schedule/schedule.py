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
from dispatcher.dispatcher_exception import DispatcherException
import threading

# Mutex lock
sql_lock = threading.Lock()

logger = logging.getLogger(__name__)
       
def schedule_update(parsed_xml: Any) -> Tuple[bool, str]:
    """Schedule a task for later execution

    @param xml: manifest to be processed
    """
    logger.debug(f"Received schedule request: {parsed_xml}")
    # TODO: Add more checking, multiple singleSchedule support, add multiple tasks, implement repeatedSchedule
    if parsed_xml.get_element('update_schedule/schedule/single_schedule/start_time'):
        task = ScheduledTask(start_time=parsed_xml.get_element('update_schedule/schedule/single_schedule/start_time'),
                             end_time=parsed_xml.get_element('update_schedule/schedule/single_schedule/end_time'),
                             manifest=parsed_xml)

        try:
            sql_lock.acquire()
            SqliteManager(UDM_DB_FILE).create_task(task)
        except DispatcherException as e:
            return False, str(e)
        finally:
            sql_lock.release()
        return True, "Task Scheduled"
    return False, "Unsupported schedule request."