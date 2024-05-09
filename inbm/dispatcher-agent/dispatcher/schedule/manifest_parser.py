import logging

from typing import Optional

from inbm_lib.xmlhandler import XmlException

from dispatcher.common.result_constants import Result
from ..common.result_constants import CODE_OK, CODE_BAD_REQUEST, CODE_MULTIPLE
from dispatcher.validators import validate_xml_manifest
from .schedule import schedule_update
from ..constants import SCHEDULE_SCHEMA_LOCATION
from dispatcher.dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)

def parse_schedule(xml: str, schema_location: Optional[str] = SCHEDULE_SCHEMA_LOCATION) -> Result:
        result: Result = Result()

        parsed_head = None
        try:
            parsed_head = \
                validate_xml_manifest(xml, schema_location=schema_location)
            is_task_scheduled, message = schedule_update(parsed_xml=parsed_head)
            logger.debug(f"is_task_scheduled={is_task_scheduled}, message={message}")
            if is_task_scheduled:
                result = Result(CODE_OK, message)
            else:
                result = Result(CODE_BAD_REQUEST, f'Error during schedule: {message}')
            return result
        except XmlException as error:
            result = Result(CODE_MULTIPLE, f'Error parsing/validating manifest: {error}')
        except DispatcherException as error:
            result = Result(CODE_BAD_REQUEST, f'Error during schedule: {error}')
        finally:
            logger.info('Schedule result: %s', str(result))
            return result
