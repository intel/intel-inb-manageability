import json
import logging
from typing import Any, Optional, Tuple
from dispatcher.config.config_command import ConfigCommand
from dispatcher.config.constants import CONFIGURATION_APPEND_REMOVE_PATHS_LIST
from dispatcher.configuration_helper import ConfigurationHelper
from dispatcher.constants import CACHE

from dispatcher.dispatcher_broker import DispatcherBroker
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager.local_repo import DirectoryRepo
from inbm_common_lib.constants import CONFIG_LOAD
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.count_down_latch import CountDownLatch
from ..common.result_constants import CODE_BAD_REQUEST, Result
from inbm_lib.xmlhandler import XmlHandler
from ..common.uri_utilities import is_valid_uri
from ..common.result_constants import CODE_OK, CODE_BAD_REQUEST, CONFIG_LOAD_FAIL_WRONG_PATH
from pathlib import Path
from inbm_common_lib.utility import remove_file

logger = logging.getLogger(__name__)

class ConfigOperation:
    def __init__(self, dispatcher_broker: DispatcherBroker) -> None:
        self._dispatcher_broker = dispatcher_broker
        
    def _do_config_operation(self, parsed_head: XmlHandler) -> Result:
        """Performs either a config load or update of config items.  Delegates to either
        do_config_install_update_config_items or do_config_install_load method depending on type
        of operation invoked

        @param parsed_head: The root parsed xml. It determines config_cmd_type
        @return (dict): returns success or failure dict from child methods
        """
        config_cmd_type, value_object = self._get_config_value(parsed_head)
        if config_cmd_type == 'load':
            return self._do_config_install_load(parsed_head=parsed_head)
        else:
            return self._do_config_install_update_config_items(config_cmd_type, value_object)

    def _get_config_value(self, parsed: XmlHandler) -> Tuple[str, Optional[str]]:
        """Get the type of config command (set_element or get_element)

        @param parsed: parsed xml element
        @return tuple: (action type, value_object)
        """
        config_cmd_type = parsed.get_element('config/cmd')
        value_object = None
        if config_cmd_type == 'set_element':
            header = parsed.get_children('config/configtype/set')
            value_object = header['path'].strip()
        elif config_cmd_type == 'get_element':
            header = parsed.get_children('config/configtype/get')
            value_object = header['path']
        elif config_cmd_type == 'append':
            header = parsed.get_children('config/configtype/append')
            value_object = header['path'].strip()
        elif config_cmd_type == 'remove':
            header = parsed.get_children('config/configtype/remove')
            value_object = header['path'].strip()
        return config_cmd_type, value_object
    
    def _do_config_install_load(self, parsed_head: XmlHandler, xml: Optional[str] = None) -> Result:
        """Invoked by do_config_operation to perform config file load. It replaces the existing
        TC conf file with a new file.

        @param parsed_head: The root parsed xml
        @param xml: Manifest to be published for Accelerator Manageability Framework agents, None for inb
        @return Result: {'status': 400, 'message': 'Configuration load: FAILED'}
        or {'status': 200, 'message': 'Configuration load: successful'}
        """
        if not self._dispatcher_broker.is_started():
            return Result(CODE_BAD_REQUEST, 'Configuration load: FAILED (mqttc not initialized)')
        configuration_helper = ConfigurationHelper(
            self._dispatcher_broker)
        uri = configuration_helper.parse_url(parsed_head)
        if not is_valid_uri(uri):
            logger.debug("Config load operation using local path.")
            path_header = parsed_head.get_children('config/configtype/load')
            new_file_loc = path_header.get('path', None)
            if CACHE not in new_file_loc.rsplit('/', 1):
                return CONFIG_LOAD_FAIL_WRONG_PATH
            if new_file_loc is None:
                return Result(CODE_BAD_REQUEST,
                              'Configuration load: Invalid configuration load manifest without <path> tag')

        if uri:
            try:
                conf_file = configuration_helper.download_config(
                    parsed_head, DirectoryRepo(CACHE))
            except DispatcherException as err:
                self._dispatcher_broker.telemetry(str(err))
                return Result(CODE_BAD_REQUEST, 'Configuration load: unable to download configuration')
            if conf_file:
                new_file_loc = get_canonical_representation_of_path(
                    str(Path(CACHE) / conf_file))

        logger.debug(f"new_file_loc = {new_file_loc}")

        try:
            self._request_config_agent(CONFIG_LOAD, file_path=new_file_loc)
            if new_file_loc:
                remove_file(new_file_loc)
            return Result(CODE_OK, 'Configuration load: SUCCESSFUL')
        except DispatcherException as error:
            remove_file(new_file_loc)
            logger.error(error)
            return Result(CODE_BAD_REQUEST, 'Configuration load: FAILED. Error: ' + str(error))

    def _do_config_install_update_config_items(self, config_cmd_type: str, value_object: Optional[str]) -> Result:
        """Invoked by do_config_operation to perform update of configuration values

        @param config_cmd_type: update
        @param value_object: key,values to updated in TC conf file
        @return dict: {'status': 400, 'message': 'Configuration update: FAILED'}
        or {'status': 200, 'message': 'Configuration update: SUCCESSFUL'}
        """
        try:
            value_list = value_object.strip().split(';') if value_object else ""

            if len(value_list) == 0 or value_object is None:
                raise DispatcherException('Invalid parameters passed in Configuration path')

            for i in range(0, len(value_list)):
                if '"' in value_list[i]:
                    raise DispatcherException("Error '\"' not allowed in config set command")

                if config_cmd_type == "append" or config_cmd_type == "remove":
                    append_remove_path = value_list[i].split(":")[0]
                    if append_remove_path not in CONFIGURATION_APPEND_REMOVE_PATHS_LIST:
                        logger.error(
                            "Given parameter doesn't support Config append or remove method...")
                        return Result(status=CODE_BAD_REQUEST, message=f'Configuration {config_cmd_type} command: FAILED')
                try:
                    self._request_config_agent(config_cmd_type, file_path=None,
                                               value_string=value_list[i])
                except DispatcherException as err:
                    logger.error(err)
                    return Result(status=CODE_BAD_REQUEST, message=f'Configuration {config_cmd_type} command: FAILED')
            return Result(status=CODE_OK, message=f'Configuration {config_cmd_type} command: SUCCESSFUL')

        except (ValueError, IndexError) as error:
            raise DispatcherException(f'Invalid values for payload {error}')

    def _request_config_agent(self, cmd_type: str, file_path: Optional[str] = None,
                              header: Optional[str] = None, value_string: Optional[str] = None) -> None:
        latch = CountDownLatch(1)
        logger.debug(" ")

        def on_command(topic: str, payload: Any, qos: int) -> None:
            logger.info('Message received: %s on topic: %s', payload, topic)

            try:
                cmd.response = json.loads(payload)

            except ValueError as error:
                logger.error('Unable to parse payload: %s', str(error))

            finally:
                # Release lock
                latch.count_down()

        cmd = ConfigCommand(cmd_type, path=file_path,
                            value_string=value_string)

        self._dispatcher_broker.mqtt_subscribe(cmd.create_response_topic(), on_command)
        self._dispatcher_broker.mqtt_publish(cmd.create_request_topic(), cmd.create_payload())

        latch.await_()
        if cmd.response is None and cmd_type != 'load':
            self._dispatcher_broker.telemetry('Failure in fetching element requested for'
                            ' command: {} header: {} path: {}'.
                            format(cmd_type, header, value_string))
            raise DispatcherException('Failure in fetching element')

        if cmd_type in ['load', 'set_element', 'append', 'remove']:
            self._dispatcher_broker.telemetry('Got response back for command: {} header: {} response: {}'.
                            format(cmd_type, header, cmd.response))

        if cmd_type == 'get_element':
            self._dispatcher_broker.telemetry('Got response back for command: {} response: {}'.
                            format(cmd_type, cmd.response))

        if type(cmd.response) is dict:
            if cmd.response is not None and 'rc' in cmd.response.keys() and cmd.response['rc'] == 1:
                raise DispatcherException(cmd.response['message'])