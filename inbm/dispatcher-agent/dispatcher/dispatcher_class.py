"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import datetime
import json
import platform
import signal
import sys
from logging.config import fileConfig
from pathlib import Path
from queue import Queue
from threading import Thread, active_count
from time import sleep
from typing import Tuple

from inbm_lib import wmi
from inbm_lib.count_down_latch import CountDownLatch
from inbm_lib.detect_os import detect_os, LinuxDistType, OsType
from inbm_lib.windows_service import WindowsService
from inbm_lib.wmi_exception import WmiException
from inbm_common_lib.constants import REMOTE_SOURCE, UNKNOWN, UNKNOWN_DATETIME, CONFIG_LOAD
from inbm_common_lib.dmi import is_dmi_path_exists, get_dmi_system_info
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.utility import remove_file
from inbm_lib.constants import QUERY_CMD_CHANNEL

from .aota.aota_error import AotaError
from .command import Command
from .common import dispatcher_state
from .common.result_constants import CODE_OK, CODE_BAD_REQUEST, CODE_MULTIPLE, \
    CONFIG_LOAD_FAIL_WRONG_PATH, CODE_FOUND
from .common.uri_utilities import is_valid_uri
from .config.config_command import ConfigCommand
from .config.constants import CONFIGURATION_APPEND_REMOVE_PATHS_LIST
from .config_dbs import ConfigDbs
from .configuration_helper import ConfigurationHelper
from .constants import *
from .device_manager.device_manager import get_device_manager
from .fota.fota_error import FotaError
from .ota_factory import OtaFactory
from .ota_target import *
from .ota_thread import ota_lock
from .packagemanager.local_repo import DirectoryRepo
from .provision_target import ProvisionTarget
from .remediationmanager.remediation_manager import RemediationManager
from .sota.os_factory import SotaOsFactory
from .sota.sota import SOTA
from .sota.sota_error import SotaError
from .workload_orchestration import WorkloadOrchestration
from inbm_lib.xmlhandler import *
from inbm_lib.version import get_friendly_inbm_version_commit
from inbm_lib.security_masker import mask_security_info

logger = logging.getLogger(__name__)


def get_log_config_path() -> str:
    """Return the config path for this agent, taken by default from LOGGERCONFIG environment
    variable and then from a fixed default path.
    """
    try:
        return os.environ['LOGGERCONFIG']
    except KeyError:
        return DEFAULT_LOGGING_PATH


def _check_type_validate_manifest(xml: str,
                                  schema_location: Optional[str] = None) -> Tuple[str, XmlHandler]:
    """Parse manifest

    @param xml: manifest in XML format
    @param schema_location: optional location of schema
    @return: Tuple of (ota-type, resource-name, URL of resource, resource-type)
    """
    # Added schema_location variable for unit tests
    schema_location = get_canonical_representation_of_path(
        schema_location) if schema_location is not None else get_canonical_representation_of_path(SCHEMA_LOCATION)
    parsed = XmlHandler(xml=xml,
                        is_file=False,
                        schema_location=schema_location)
    type_of_manifest = parsed.get_element('type')
    logger.debug(
        f"type_of_manifest: {type_of_manifest!r}. parsed: {mask_security_info(str(parsed))!r}.")
    return type_of_manifest, parsed


def _get_config_value(parsed: XmlHandler) -> Tuple[str, Optional[str]]:
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


class Dispatcher(WindowsService):
    """An instance of this class will be the callback to
    L{TestAdapter} and L{HdcAdapter} to enable the cloud connectors to
    call the OTA tools
    """

    _svc_name_ = 'inbm-dispatcher'
    _svc_display_name_ = 'Dispatcher Agent'
    _svc_description_ = 'Intel Manageability coordinating agent'

    def __init__(self, args: Optional[List] = None, broker_core: Optional[DispatcherBroker] = None) -> None:
        if args is None:
            args = []

        super().__init__(args)

        log_config_path = get_log_config_path()
        msg = f"Looking for logging configuration file at {log_config_path}"
        print(msg)
        fileConfig(log_config_path,
                   disable_existing_loggers=False)

        if broker_core is not None:
            self._broker = broker_core
        else:
            self._broker = DispatcherBroker()
        self.update_queue: Queue[Tuple[str, str]] = Queue(1)
        self._thread_count = 1
        self.sota_repos = None
        self.device_manager = get_device_manager()
        self.config_dbs = ConfigDbs.WARN
        self.dbs_remove_image_on_failed_container = True
        self.host_with_nodes = HOST_WITH_NODES_DEFAULT
        self.proceed_without_rollback = PROCEED_WITHOUT_ROLLBACK_DEFAULT
        self.diag_health_report = {'rc': -1,
                                   'cmd': 'diagnostic OR MQTT',
                                   'message': 'No health report from diagnostic'}
        self.RUNNING = False
        self.remediation_instance = RemediationManager(self._make_callbacks_object())
        self._wo: Optional[WorkloadOrchestration] = None

    def _make_callbacks_object(self) -> DispatcherCallbacks:
        return DispatcherCallbacks(install_check=self.install_check,
                                   sota_repos=self.sota_repos,
                                   proceed_without_rollback=self.proceed_without_rollback,
                                   broker_core=self._broker)

    def svc_stop(self) -> None:
        self.RUNNING = False

    def svc_main(self) -> None:
        self.start()

    def start(self, tls: bool = True) -> None:
        """Start the Dispatcher service.

        Call this directly for Linux and indirectly through svc_main for Windows.

        Initializes the MQTT connection and runs Remediation manager

        @param tls: Transport level security;  Default=True
        """

        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 8:
            logger.error(
                "Python version must be 3.8 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)
        self.RUNNING = True
        logger.info("Dispatcher agent starting. Version info: " +
                    get_friendly_inbm_version_commit())
        self._broker.start(tls)
        self._initialize_broker()

        self.remediation_instance.run()

        logger.debug("Waiting for 5 secs for config to send dispatcher's config items")
        sleep(5)

        with ota_lock:
            self._perform_startup_tasks()

        def _sig_handler(signo, frame):
            """Callback to register different signals. Currently we do that only for SIGTERM & SIGINT

            @param signo: currently SIGTERM & SIGINT
            @param frame:
            """

            if signo in (signal.SIGINT, signal.SIGTERM):
                self.RUNNING = False

        if platform.system() != 'Windows':
            # Catch ctrl+C from user
            signal.signal(signal.SIGINT, _sig_handler)
            # Catch termination via systemd
            signal.signal(signal.SIGTERM, _sig_handler)

        self._broker.mqtt_publish(f'{AGENT}/state', 'running', retain=True)

        active_start_count = active_count()
        while self.RUNNING:
            if not self.update_queue.empty():
                if active_count() - active_start_count < self._thread_count:
                    worker = Thread(target=handle_updates, args=(self,))
                    worker.setDaemon(True)
                    worker.start()
            sleep(1)

        self._broker.mqtt_publish(f'{AGENT}/state', 'dead', retain=True)
        self._broker.stop()

    def _perform_startup_tasks(self) -> None:
        """Perform one-time dispatcher startup tasks
        @return: None
        """
        try:
            self.check_dispatcher_state_info()
        except DispatcherException as e:  # pragma: no cover
            self._telemetry('Error reading or parsing dispatcher state file on startup')
            logger.error('Error reading or parsing dispatcher state file on startup ' + str(e))
            try:
                dispatcher_state.clear_dispatcher_state()
            except OSError as e:
                self._telemetry('Error cleaning up dispatcher state on startup')
                logger.error('Error cleaning up dispatcher state on startup ' + str(e))
            # in case we have a pending mender revert
            detected_os = detect_os()
            if detected_os in [LinuxDistType.YoctoARM.name, LinuxDistType.YoctoX86_64.name]:
                try:
                    SotaOsFactory(self._make_callbacks_object()).get_os(detected_os).create_snapshotter('update',
                                                                                                        snap_num='1',
                                                                                                        proceed_without_rollback=True).commit()
                except OSError:
                    # harmless here--mender commit is speculative
                    pass
        self.create_workload_orchestration_instance()
        self.invoke_workload_orchestration_check(True)

    def _do_config_install_load(self, parsed_head: XmlHandler, target_type: str,
                                xml: str = None) -> Result:
        """Invoked by do_config_operation to perform config file load. It replaces the existing
        TC conf file with a new file.

        @param parsed_head: The root parsed xml
        @param target_type: Target type (vision/node), None for inb
        @param xml: Manifest to be published for Accelerator Manageability Framework agents, None for inb
        @return Result: {'status': 400, 'message': 'Configuration load: FAILED'}
        or {'status': 200, 'message': 'Configuration load: successful'}
        """
        if not self._broker.is_started():
            return Result(CODE_BAD_REQUEST, 'Configuration load: FAILED (mqttc not initialized)')
        configuration_helper = ConfigurationHelper(self._make_callbacks_object())
        uri = configuration_helper.parse_url(parsed_head)
        if not is_valid_uri(uri):
            if target_type is TargetType.none.name:
                logger.debug("Config load operation using local path.")
                path_header = parsed_head.get_children('config/configtype/load')
                new_file_loc = path_header.get('path', None)
                if CACHE not in new_file_loc.rsplit('/', 1):
                    return CONFIG_LOAD_FAIL_WRONG_PATH
                if new_file_loc is None:
                    return Result(CODE_BAD_REQUEST,
                                  'Configuration load: Invalid configuration load manifest without <path> tag')
            else:
                return Result(CODE_BAD_REQUEST, 'Configuration load: unable to download configuration (bad URI)')

        if uri:
            try:
                conf_file = configuration_helper.download_config(
                    parsed_head, DirectoryRepo(CACHE))
            except DispatcherException as err:
                self._telemetry(str(err))
                return Result(CODE_BAD_REQUEST, 'Configuration load: unable to download configuration')
            if conf_file:
                new_file_loc = get_canonical_representation_of_path(
                    str(Path(CACHE) / conf_file))

        logger.debug(f"new_file_loc = {new_file_loc}")

        if target_type is TargetType.none.name:
            try:
                self._request_config_agent(CONFIG_LOAD, file_path=new_file_loc)
                if new_file_loc:
                    remove_file(new_file_loc)
                return Result(CODE_OK, 'Configuration load: SUCCESSFUL')
            except DispatcherException as error:
                remove_file(new_file_loc)
                logger.error(error)
                return Result(CODE_BAD_REQUEST, 'Configuration load: FAILED')
        else:
            if xml is None:
                return Result(CODE_BAD_REQUEST, 'Configuration load: FAILED. No XML to publish to targets')

            target_config_load_operation(
                xml=xml, file_path=new_file_loc, broker_core=self._broker)
            return PUBLISH_SUCCESS

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
                            "Given parameters doesn't support Config append or remove method...")
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

    def _do_config_operation(self, parsed_head: XmlHandler, target_type: str) -> Result:
        """Performs either a config load or update of config items.  Delegates to either
        do_config_install_update_config_items or do_config_install_load method depending on type
        of operation invoked

        @param parsed_head: The root parsed xml. It determines config_cmd_type
        @return (dict): returns success or failure dict from child methods
        """
        try:
            self.install_check(check_type='check_network')
        except DispatcherException:
            return Result(CODE_MULTIPLE, 'Network and Cloud check failed')

        config_cmd_type, value_object = _get_config_value(parsed_head)
        if config_cmd_type == 'load':
            return self._do_config_install_load(parsed_head=parsed_head, target_type=target_type)
        else:
            return self._do_config_install_update_config_items(config_cmd_type, value_object)

    def _perform_cmd_type_operation(self, parsed_head: XmlHandler, xml: str) -> Result:
        """Performs either a reboot or shutdown or decommission based on type
        of command sent.

        @param parsed_head: The root parsed xml. It determines cmd type
        @return (dict): returns success or failure dict from child methods
        """
        cmd = parsed_head.get_element('cmd')
        target_type = parsed_head.find_element('*/targetType')

        if cmd == "shutdown":
            message = self.device_manager.shutdown()
        elif cmd == "restart":
            if target_type is None:
                message = self.device_manager.restart()
                if message == SUCCESS_RESTART:
                    state = {'restart_reason': 'restart_cmd'}
                    dispatcher_state.write_dispatcher_state_to_state_file(state)
            else:
                message = self._do_restart_on_target(xml)
        elif cmd == "query":
            if target_type is None:
                self._broker.mqtt_publish(QUERY_CMD_CHANNEL, xml)
            elif target_type == "node":
                self._broker.mqtt_publish(VISION_CMD_QUERY, xml)
            return PUBLISH_SUCCESS
        elif cmd == "custom":
            header = parsed_head.get_children('custom')
            json_data = header['data']
            self._broker.mqtt_publish(CUSTOM_CMD_CHANNEL, json_data)
            return PUBLISH_SUCCESS
        elif cmd == "provisionNode":
            ProvisionTarget(xml, self._make_callbacks_object()).install(parsed_head)
            return PUBLISH_SUCCESS
        elif cmd == "decommission":
            message = self.device_manager.decommission()
        else:
            error = "Unsupported command: " + cmd
            raise DispatcherException(error)
        return Result(CODE_OK, message)

    def _telemetry(self, message: str) -> None:
        self._broker.telemetry(message)

    def _send_result(self, message: str) -> None:
        """Sends event messages to local MQTT channel

        @param message: message to be published to cloud
        """
        self._broker.send_result(message)

    def do_install(self, xml: str, schema_location: Optional[str] = None) -> int:
        """Delegates the installation to either
        . call a DeviceManager command
        . do_ota_install
        . do_config_operation

        Call parse and install functions in Dispatcher
        """
        result: Result = Result()
        logger.debug("do_install")
        parsed_head = None
        try:  # TODO: Split into multiple try/except blocks
            type_of_manifest, parsed_head = \
                _check_type_validate_manifest(xml, schema_location=schema_location)
            self.invoke_workload_orchestration_check(False, type_of_manifest, parsed_head)

            if type_of_manifest == 'cmd':
                logger.debug("Running command sent down ")
                result = self._perform_cmd_type_operation(parsed_head, xml)
            elif type_of_manifest == 'ota':
                # Parse manifest
                header = parsed_head.get_children('ota/header')
                ota_type = header['type']
                repo_type = header['repo']
                resource = parsed_head.get_children(f'ota/type/{ota_type}')
                kwargs = {'ota_type': ota_type}
                target_type = resource.get('targetType', None)

                if target_type is None:
                    target_type = TargetType.none.name
                logger.debug(f"Target type: {target_type}")

                if target_type is TargetType.none.name and ota_type == OtaType.POTA.name.lower():
                    ota_list = self._create_ota_resource_list(parsed_head, resource)
                    # Perform manifest checking first before OTA
                    self._validate_pota_manifest(
                        repo_type, target_type, kwargs, parsed_head, ota_list)

                    for ota in sorted(ota_list.keys()):
                        kwargs['ota_type'] = ota
                        result = self._do_ota_update(
                            xml, ota, repo_type, target_type, ota_list[ota], kwargs, parsed_head)
                        if result == Result(CODE_BAD_REQUEST, "FAILED TO INSTALL") or result == OTA_FAILURE:
                            break
                else:
                    result = self._do_ota_update(
                        xml, ota_type, repo_type, target_type, resource, kwargs, parsed_head)

            elif type_of_manifest == 'config':
                logger.debug('Running configuration command sent down ')
                target_type = parsed_head.find_element('config/targetType')
                if target_type is None:
                    target_type = TargetType.none.name
                logger.debug(f"target_type : {target_type}")
                if target_type is TargetType.none.name:
                    result = self._do_config_operation(parsed_head, target_type)
                else:
                    config_cmd_type = parsed_head.get_element('config/cmd')
                    logger.debug(f"cmd_type : {config_cmd_type}")
                    result = self._do_config_operation_on_target(
                        config_cmd_type, parsed_head, xml, target_type, self._broker)
        except (DispatcherException, UrlSecurityException) as error:
            logger.error(error)
            result = Result(CODE_BAD_REQUEST, f'Error during install: {error}')
        except XmlException as error:
            result = Result(CODE_MULTIPLE, f'Error parsing/validating manifest: {error}')
        except (AotaError, FotaError, SotaError) as e:
            result = Result(CODE_BAD_REQUEST, str(e))
        finally:
            logger.info('Install result: %s', str(result))
            self._send_result(str(result))
            if result.status != CODE_OK and parsed_head:
                self.invoke_workload_orchestration_check(True, type_of_manifest, parsed_head)
            return result.status

    def _create_ota_resource_list(self, parsed_head: XmlHandler, resource: Dict) -> Dict[str, Any]:
        """Creates a list of OTA commands requested under POTA along with the resources and arguments
        associated with each OTA

        @param parsed_head: Parsed head of the manifest xml
        @param resource: resource to parse
        @return Dict: A dict containing all the OTAs to be performed
        """
        ota_resource_dict = {}
        for key in resource.keys():
            ota_resource = parsed_head.get_children(f'ota/type/pota/{key}')
            if key == 'fota':
                ota_resource['holdReboot'] = True
            ota_resource_dict[key] = ota_resource
        logger.debug("DICT: {} parsed_head :{}, resource:{}".format(
            ota_resource_dict, parsed_head, resource))
        return ota_resource_dict

    def _do_ota_update(self, xml: str, ota_type: str, repo_type: str, target_type: Optional[str], resource: Dict,
                       kwargs: Dict, parsed_head: XmlHandler) -> Result:
        """Performs OTA updates by creating a thread based on OTA factory detected from the manifest

        @param xml: manifest in XML format
        @param ota_type: Type of OTA requested (AOTA/FOTA/SOTA)
        @param repo_type: Type of repo to fetch files (local/remote)
        @param target_type: Target on which the config operation needs to be performed
        @param resource: resource to parse
        @param kwargs: arguments dictionary to be updated after parsing resources
        @param parsed_head: Parsed head of the manifest xml
        @return Result: PUBLISH_SUCCESS if success
        """
        logger.debug("")
        factory = OtaFactory.get_factory(
            ota_type.upper(),
            repo_type,
            self._make_callbacks_object(),
            self.config_dbs)

        p = factory.create_parser()
        # NOTE: p.parse can raise one of the *otaError exceptions
        parsed_manifest = p.parse(resource, kwargs, parsed_head)
        self.check_username_password(parsed_manifest)

        # target_type is only used for Accelerator Manageability Framework
        if target_type is TargetType.none.name:
            t = factory.create_thread(parsed_manifest)
            return t.start()
        else:
            return self._do_install_on_target(
                ota_type.upper(), xml, repo_type, parsed_manifest)

    def _validate_pota_manifest(self, repo_type: str, target_type: Optional[str],
                                kwargs: Dict, parsed_head: XmlHandler, ota_list: Dict) -> None:
        """Validate POTA manifest by checking FOTA and SOTA information before starting OTA.

        @param repo_type: Type of repo to fetch files (local/remote)
        @param target_type: Target on which the config operation needs to be performed
        @param kwargs: arguments dictionary to be updated after parsing resources
        @param parsed_head: Parsed head of the manifest xml
        """
        logger.debug("")
        for ota in sorted(ota_list.keys()):
            # target_type is only used for Accelerator Manageability Framework
            logger.debug(f"ota = {ota}")
            if target_type is TargetType.none.name:
                logger.debug("")
                factory = OtaFactory.get_factory(
                    ota.upper(),
                    repo_type,
                    self._make_callbacks_object(),
                    self.config_dbs)
                p = factory.create_parser()
                # NOTE: p.parse can raise one of the *otaError exceptions
                parsed_manifest = p.parse(ota_list[ota], kwargs, parsed_head)
                t = factory.create_thread(parsed_manifest)
                t.check()
            logger.debug(f'{ota} checks complete.')

    def check_username_password(self, parsed_manifest: Mapping[str, Optional[Any]]) -> None:
        """Check if the manifest miss username or password"""
        if parsed_manifest['ota_type'] == OtaType.POTA.name.lower():
            for ota_key in parsed_manifest.keys():
                if ota_key == OtaType.FOTA.name.lower() or ota_key == OtaType.SOTA.name.lower():
                    manifest_ota = parsed_manifest[ota_key]
                    if manifest_ota is None:
                        raise DispatcherException(f"{ota_key} is None in parsed manifest")
                    usr = manifest_ota['username']
                    pwd = manifest_ota['password']
                    self._verify_username_password_present(usr, pwd, ota_key)
        else:
            if 'ota_type' in parsed_manifest:
                ota_type = parsed_manifest['ota_type']
            else:
                raise DispatcherException(f'No ota_type in manifest')
            if ota_type is None:
                raise DispatcherException('ota_type is None')

            self._verify_username_password_present(
                usr=parsed_manifest['username'],
                pwd=parsed_manifest['password'],
                ota=ota_type)

    def _verify_username_password_present(self, usr: Optional[str], pwd: Optional[str], ota: str) -> None:
        if usr and (pwd is None):
            raise DispatcherException(f'No Password sent in manifest for {ota}')
        elif (usr is None) and pwd:
            raise DispatcherException(f'No Username sent in manifest for {ota}')

    def _do_config_operation_on_target(self, config_cmd: str, parsed_head: XmlHandler, xml: str, target_type: str,
                                       broker_core: DispatcherBroker) -> Result:
        """Performs config operations on Accelerator Manageability Framework agents

        @param config_cmd: Config cmd to be performed on targets
        @param parsed_head: Parsed head of the manifest xml
        @param xml: manifest in XML format
        @param target_type: Target on which the config operation needs to be performed
        @param broker_core: Dispatcher Broker object
        @return Result: PUBLISH_SUCCESS if success
        @raises DispatcherException: if unsuccessful or if MQTT object is None
        """
        logger.debug("")
        if config_cmd == CONFIG_LOAD:
            return self._do_config_install_load(parsed_head=parsed_head, target_type=target_type, xml=xml)
        else:
            broker_core.mqtt_publish(CONFIG_CHANNEL + config_cmd, xml)
            return PUBLISH_SUCCESS

    def _do_restart_on_target(self, xml: str) -> Result:
        logger.debug("")
        self._broker.mqtt_publish(TARGET_CMD_RESTART, xml)
        return PUBLISH_SUCCESS

    def _do_install_on_target(self, ota_type: str, xml: str, repo_type: str, parsed_manifest: Mapping[str, Optional[Any]]):
        logger.debug("")
        t = OtaTarget(xml, parsed_manifest, ota_type,
                      self._make_callbacks_object())
        target_ota_status = t.install()
        logger.debug(f"Install on Target STATUS: {target_ota_status}")
        return target_ota_status

    def _request_config_agent(self, cmd_type: str, file_path: Optional[str] = None,
                              header: Optional[str] = None, value_string: Optional[str] = None) -> None:
        latch = CountDownLatch(1)
        logger.debug(" ")

        def on_command(topic: str, payload: str, qos: int) -> None:
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

        self._broker.mqtt_subscribe(cmd.create_response_topic(), on_command)
        self._broker.mqtt_publish(cmd.create_request_topic(), cmd.create_payload())

        latch.await_()
        if cmd.response is None and cmd_type != 'load':
            self._telemetry('Failure in fetching element requested for'
                            ' command: {} header: {} path: {}'.
                            format(cmd_type, header, value_string))
            raise DispatcherException('Failure in fetching element')

        if cmd_type in ['load', 'set_element', 'append', 'remove']:
            self._telemetry('Got response back for command: {} header: {} response: {}'.
                            format(cmd_type, header, cmd.response))

        if cmd_type == 'get_element':
            self._telemetry('Got response back for command: {} response: {}'.
                            format(cmd_type, cmd.response))

        if type(cmd.response) is dict:
            if cmd.response is not None and 'rc' in cmd.response.keys() and cmd.response['rc'] == 1:
                raise DispatcherException(cmd.response['message'])

    def install_check(self, size: Optional[int] = None, check_type: Optional[str] = None) -> None:
        """Perform pre install checks via the diagnostic agent. Send a command <pre_ota_check> to
        diagnostic agent which checks [cloud agent, cloud, memory, storage, battery]

        @param size: size of the install package; default=None
        @param check_type : String representation of checks
        eg: check_type='check_storage'..could later be extended to other types
        """

        # Create command object for pre install check
        cmd = Command(check_type, self._broker) if check_type else Command(
            'install_check', self._broker)

        cmd.execute()

        if cmd.log_info != "":
            logger.info(cmd.log_info)
        if cmd.log_error != "":
            logger.error(cmd.log_error)

        if cmd.response is None:
            self._telemetry('Install check timed out. Please '
                            'check health of the diagnostic agent')
            raise DispatcherException('Install check timed out')

        if cmd.response['rc'] == 0:
            self._telemetry('Command: {} passed. Message: {}'
                            .format(cmd.command, cmd.response['message']))
            logger.info('Install check passed')

        else:
            self._telemetry('Command: {} failed. Message: {}'
                            .format(cmd.command, cmd.response['message']))
            raise DispatcherException('Install check failed')

    def _on_cloud_request(self, topic: str, payload: str, qos: int) -> None:
        """Called when a message is received from cloud

        @param topic: incoming topic
        @param payload: incoming payload
        @param qos: quality of service level
        """
        logger.info('Cloud request received: %s on topic: %s',
                    mask_security_info(payload), topic)
        request_type = topic.split('/')[-1]
        manifest = payload
        if not self.update_queue.full():
            self.update_queue.put((request_type, manifest))
        else:
            self._send_result(
                str(Result(CODE_FOUND, "OTA In Progress, Try Later")))

    def _on_message(self, topic: str, payload: str, qos: int) -> None:
        """Called when a message is received from _telemetry-agent

        @param topic: incoming topic
        @param payload: incoming payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)

    def _initialize_broker(self):
        """Set up initial subscription topics. The callbacks have following purposes:

        a.) _on_message : called when a message is received from _telemetry agent
        b.) _on_cloud_request: called when a message is received from cloud
        c.) override_defaults: called when config agent sends updates value
        """

        def override_defaults(topic: str, payload: str, qos: int) -> None:
            """Called when config agent sends updates value

            @param topic: incoming topic
            @param payload: incoming payload
            @param qos: quality of service level
            """
            logger.info('Message received: %s on topic: %s', payload, topic)
            config_name = topic.split('/')[-1]

            def config_sanitize(the_payload: Any) -> Any:
                if the_payload.lower() == "true":
                    return True
                elif the_payload.lower() == "false":
                    return False
                elif the_payload.lower() == "null":
                    return None
                elif the_payload:
                    return the_payload

            cleaned_payload = None
            try:
                payload = json.loads(payload)
                cleaned_payload = config_sanitize(payload)
            except DispatcherException:
                pass

            logger.debug("Considering config key/value " + str(config_name) + " " +
                         str(cleaned_payload))

            if config_name == "dbs":
                if cleaned_payload in ConfigDbs.ON.value:
                    self.config_dbs = ConfigDbs.ON
                elif cleaned_payload in ConfigDbs.WARN.value:
                    self.config_dbs = ConfigDbs.WARN
                elif cleaned_payload in ConfigDbs.OFF.value:
                    self.config_dbs = ConfigDbs.OFF
                else:
                    if cleaned_payload is not None:
                        logger.error("Invalid DBS mode selected: " + str(cleaned_payload))
                    else:
                        logger.error("No DBS mode selected!")
                    return

                if self.config_dbs == ConfigDbs.ON:
                    self.remediation_instance.ignore_dbs_results = False
                elif self.config_dbs == ConfigDbs.WARN:
                    self.remediation_instance.ignore_dbs_results = True

            if config_name == "dbsRemoveImageOnFailedContainer":
                if cleaned_payload is None:
                    logger.error("No dbsRemoveImageOnFailedContainer selected!")
                else:
                    self.remediation_instance.dbs_remove_image_on_failed_container = cleaned_payload
                    self.dbs_remove_image_on_failed_container = cleaned_payload

            if config_name == "proceedWithoutRollback":
                if cleaned_payload is None:
                    logger.error("No proceedWithoutRollback selected!")
                else:
                    self.proceed_without_rollback = cleaned_payload

            if config_name == "ubuntuAptSource":
                if cleaned_payload is None:
                    logger.error("No ubuntuAptSource selected!")
                else:
                    self.sota_repos = cleaned_payload

        try:
            logger.debug('Subscribing to: %s', STATE_CHANNEL)
            self._broker.mqtt_subscribe(STATE_CHANNEL, self._on_message)

            logger.debug('Subscribing to: %s', CONFIGURATION_DISPATCHER_UPDATE_CHANNEL)
            self._broker.mqtt_subscribe(
                CONFIGURATION_DISPATCHER_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', CONFIGURATION_SOTA_UPDATE_CHANNEL)
            self._broker.mqtt_subscribe(CONFIGURATION_SOTA_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', CONFIGURATION_ALL_AGENTS_UPDATE_CHANNEL)
            self._broker.mqtt_subscribe(
                CONFIGURATION_ALL_AGENTS_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', TC_REQUEST_CHANNEL)
            self._broker.mqtt_subscribe(TC_REQUEST_CHANNEL, self._on_cloud_request)

        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)

    def invoke_sota(self, **kwargs) -> None:
        """Invokes SOTA in either snapshot_revert or snapshot_delete mode along with snapshot_num

        @param kwargs: dict value containing action='snapshot_revert' or 'snapshot_delete',
        snapshot_num
        """
        logger.debug('Invoking SOTA')

        parsed_manifest = {'sota_cmd': 'rollback', 'log_to_file': None,
                           'sota_repos': self.sota_repos,
                           'uri': None, 'signature': None, 'hash_algorithm': None,
                           'username': None, 'password': None, 'release_date': None}
        sota_instance = SOTA(parsed_manifest, REMOTE_SOURCE, self._make_callbacks_object(),
                             **kwargs)

        sota_instance.execute(self.proceed_without_rollback)

    def create_workload_orchestration_instance(self) -> None:
        """This method used to create WorkloadOrchestration instance.
        """
        self._wo = WorkloadOrchestration(self._make_callbacks_object())

    def invoke_workload_orchestration_check(self, online_mode: bool, type_of_manifest: Optional[str] = None, parsed_head: Optional[XmlHandler] = None) -> None:
        """This method is used to invoke workload orchestration checks at startup and before/after any OTA update that performs shutdown/reboot within.

        @param online_mode: boolean to indicate node status to be online mode
        @param type_of_manifest: type of manifest
        @param parsed_head: root of parsed xml
        """
        if self._wo is not None:
            if not type_of_manifest or type_of_manifest == 'cmd':
                self._wo.set_workload_orchestration_mode(online_mode)

            if type_of_manifest == 'ota' and parsed_head:
                ota_type = parsed_head.get_children('ota/header')['type']
                if ota_type in [OtaType.SOTA.name.lower(), OtaType.FOTA.name.lower(), OtaType.POTA.name.lower()]:
                    self._wo.set_workload_orchestration_mode(online_mode)

    def check_dispatcher_state_info(self) -> None:
        """This method is always called on restarting dispatcher.  If there is a dispatcher state
        file existing, then it checks for the restart reason.
        If the restart reason is SOTA, check_sota_state function continues
        If the restart reason is FOTA, check_fota_state function continues 
        If the restart reason is POTA, both SOTA and FOTA info is checked.
        """
        def _check_sota_state() -> None:
            """If the restart reason is SOTA then it waits for diag agent to respond with health report. If the wait
            times-outs or in case of bad health report, it performs a SOTA rollback
            In case of a good health report, it just deletes the snapshot."""
            try:
                self.install_check(check_type='swCheck')
                self.install_check(check_type='check_network')
                self._telemetry('On Boot, Diagnostics reports healthy system')
                self.invoke_sota(action='diagnostic_system_healthy', snapshot=None)
            except DispatcherException:
                self._telemetry(
                    'On Boot, Diagnostics reports some services not up after previous SOTA')
                self.invoke_sota(action='diagnostic_system_unhealthy', snapshot=None)

        def _check_fota_state(fota_state: Dict) -> None:
            """This method checks the FOTA info in dispatcher state file and validates the release date
            and bios version number within the file to match the device's fw info and sends the _telemetry 
            info accordingly based on the validation of information above.

            @params fota_state: The consumed information from the dispatcher state file.
            """
            os_type = platform.system()
            platform_info = PlatformInformation()
            try:
                ds_bios_version = str(fota_state['bios_version'])
                ds_rel_date = str(fota_state['release_date'])
                if os_type == OsType.Linux.name:
                    if is_dmi_path_exists():
                        logger.debug("Getting BIOS information from DMI path")
                        platform_info = get_dmi_system_info()
                    else:
                        logger.debug("Checking device_tree information")
                        platform_info = get_device_tree_system_info()
                        logger.debug("Device-Tree parsed successfully")
                    if UNKNOWN in [platform_info.bios_version, platform_info.bios_release_date]:
                        self._send_result(
                            "FOTA INSTALL UNKNOWN: Error gathering BIOS information.")
                        return
                else:
                    platform_info.bios_version = wmi.wmic_query('bios', 'caption')['Caption']
                    platform_info.bios_release_date = datetime.datetime.strptime(wmi.wmic_query(
                        'bios', 'releasedate')['ReleaseDate'], '%Y%m%d000000.000000+000')
            except (KeyError, ValueError, FotaError, WmiException) as e:
                self._send_result(
                    f"FOTA INSTALL UNKNOWN: Error gathering BIOS information: {e}")
                return
            logger.debug("FW version on system:{} , FW rel date on system: {}".format(
                platform_info.bios_version, platform_info.bios_release_date))
            if platform_info.bios_release_date != ds_rel_date and platform_info.bios_version != ds_bios_version:
                self._send_result(
                    "SUCCESSFUL INSTALL: Overall FOTA update successful. "
                    "System has been updated with new Firmware version...")
            else:
                self._send_result(
                    "FAILED INSTALL: Overall FOTA update failed. Firmware not updated.")

        if dispatcher_state.is_dispatcher_state_file_exists():
            state = dispatcher_state.consume_dispatcher_state_file(read=True)
            if state is None:
                raise DispatcherException("Unable to get dispatcher state file")
            logger.debug(str(state))
            try:
                restart_reason = str(state['restart_reason'])
            except KeyError:
                if 'mender-version' in state:
                    restart_reason = 'sota'
                else:
                    raise DispatcherException(
                        "The dispatcher state file doesn't contain 'restart_reason' key...")
            if OtaType.FOTA.name.lower() in restart_reason:
                _check_fota_state(state)
            elif OtaType.POTA.name.lower() in restart_reason:
                _check_fota_state(state)
                _check_sota_state()
            elif 'restart' in restart_reason:
                self._send_result("Reboot SUCCESSFUL.")
            else:
                _check_sota_state()

            dispatcher_state.clear_dispatcher_state()
        else:
            self._telemetry('Dispatcher detects normal boot sequence')


def handle_updates(dispatcher: Any) -> None:
    """Global function to handle multiple requests from cloud using a FIFO queue.

    @param dispatcher: callback to dispatcher
    """
    message: Tuple[str, str] = dispatcher.update_queue.get()
    request_type: str = message[0]
    manifest: str = message[1]

    if request_type == "install" or request_type == "query":
        dispatcher.do_install(xml=manifest)
        return

    try:
        if request_type == "shutdown" or request_type == "restart" or request_type == "decommission":
            dispatcher.invoke_workload_orchestration_check(False)
        if request_type == "shutdown":
            result = dispatcher.device_manager.shutdown()
        elif request_type == "restart":
            result = dispatcher.device_manager.restart()
        elif request_type == "decommission":
            result = dispatcher.device_manager.decommission()
        else:
            logger.error("Request not supported: " + request_type)
            return
    except (NotImplementedError, DispatcherException) as e:
        dispatcher._send_result(str(Result(CODE_BAD_REQUEST, str(e))))
        dispatcher.invoke_workload_orchestration_check(True)
    else:
        dispatcher._send_result(str(Result(CODE_OK, result)))
