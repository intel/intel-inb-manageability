"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import datetime
import json
import platform
import signal
import sys
from queue import Queue
from threading import Thread, active_count, Lock
from time import sleep
from typing import Optional, Any, Mapping, Tuple, Sequence

from dispatcher.config.config_operation import ConfigOperation
from dispatcher.source.source_command import do_source_command
from dispatcher.common.result_constants import Result, PUBLISH_SUCCESS, OTA_FAILURE

from .install_check_service import InstallCheckService

from inbm_lib import wmi
from inbm_lib.detect_os import detect_os, LinuxDistType, OsType
from inbm_lib.wmi_exception import WmiException
from inbm_lib.validate_package_list import parse_and_validate_package_list
from inbm_lib.constants import QUERY_CMD_CHANNEL, OTA_SUCCESS, FAIL
from inbm_common_lib.constants import REMOTE_SOURCE, UNKNOWN
from inbm_common_lib.dmi import is_dmi_path_exists, get_dmi_system_info
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.exceptions import UrlSecurityException

from .schedule.manifest_parser import ScheduleManifestParser, SCHEDULE_SCHEMA_LOCATION
from .schedule.schedules import Schedule
from .schedule.sqlite_manager import SqliteManager
from .schedule.apscheduler import APScheduler
from .dispatcher_broker import DispatcherBroker
from .dispatcher_exception import DispatcherException
from .aota.aota_error import AotaError
from .source.source_exception import SourceError
from .common import dispatcher_state
from .common.result_constants import CODE_OK, CODE_BAD_REQUEST, CODE_MULTIPLE, \
    CODE_FOUND
from .config_dbs import ConfigDbs
from .constants import *
from .device_manager.device_manager import get_device_manager
from .fota.fota_error import FotaError
from .ota_factory import OtaFactory
from .ota_thread import ota_lock
from .ota_util import create_ota_resource_list
from .remediationmanager.remediation_manager import RemediationManager
from .sota.os_factory import SotaOsFactory
from .sota.sota import SOTA
from .sota.sota_error import SotaError
from .workload_orchestration import WorkloadOrchestration
from inbm_lib.xmlhandler import *
from inbm_lib.version import get_friendly_inbm_version_commit
from inbm_lib.security_masker import mask_security_info
from .update_logger import UpdateLogger
from . import source

logger = logging.getLogger(__name__)
# Mutex lock
sql_lock = Lock()


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


class Dispatcher:
    def __init__(self, args: list[str], broker: DispatcherBroker, install_check_service: InstallCheckService) -> None:
        self._dispatcher_broker = broker
        self._install_check_service = install_check_service
        # Initialize update_queue with a capacity of 1 to ensure serialized handling of updates.
        self.update_queue: Queue[Tuple[str, str, Optional[str]]] = Queue(1)
        self._thread_count = 1
        self._sota_repos = None
        self.sota_mode = None
        self._package_list: str = ""

        self.device_manager = get_device_manager()
        self.config_dbs = ConfigDbs.WARN
        self.dbs_remove_image_on_failed_container = True
        self.proceed_without_rollback = PROCEED_WITHOUT_ROLLBACK_DEFAULT
        self.diag_health_report = {'rc': -1,
                                   'cmd': 'diagnostic OR MQTT',
                                   'message': 'No health report from diagnostic'}
        self.RUNNING = False
        self._update_logger = UpdateLogger(ota_type="", data="")
        self.remediation_instance = RemediationManager(
            self._dispatcher_broker)
        self._wo: Optional[WorkloadOrchestration] = None

        self._config_operation = ConfigOperation(self._dispatcher_broker)

        self.sqlite_mgr = SqliteManager()
        self.ap_scheduler = APScheduler(sqlite_mgr=self.sqlite_mgr)

    def stop(self) -> None:
        self.RUNNING = False

    def start(self, tls: bool = True) -> None:
        """Start the Dispatcher service.

        Call this directly for Linux and indirectly through svc_main for Windows.

        Initializes the MQTT connection and runs Remediation manager

        @param tls: Transport level security;  Default=True
        """

        if sys.version_info[0] < 3 or sys.version_info[0] == 3 and sys.version_info[1] < 11:
            logger.error(
                "Python version must be 3.11 or higher. Python interpreter version: " + sys.version)
            sys.exit(1)
        self.RUNNING = True
        logger.info("Dispatcher agent starting. Version info: " +
                    get_friendly_inbm_version_commit())
        self._dispatcher_broker.start(tls)
        self._initialize_broker()

        self.remediation_instance.run()

        logger.debug("Waiting for 5 secs for config to send dispatcher's config items")
        sleep(5)

        with ota_lock:
            self._perform_startup_tasks()

        # Run scheduler to schedule the task during startup.
        single_schedules = self.sqlite_mgr.get_all_single_schedules_in_priority_order()
        logger.info(f"Total single scheduled tasks: {len(single_schedules)}")
        for single_schedule in single_schedules:
            self.ap_scheduler.add_single_schedule_job(self.do_install, single_schedule)
            logger.debug(f"Scheduled single job: {single_schedule}")

        repeated_schedules = self.sqlite_mgr.get_all_repeated_schedules_in_priority_order()
        logger.info(f"Total repeated scheduled jobs: {len(repeated_schedules)}")
        for repeated_schedule in repeated_schedules:
            self.ap_scheduler.add_repeated_schedule_job(self.do_install, repeated_schedule)
            logger.debug(f"Scheduled repeated job: {repeated_schedule}")
        self.ap_scheduler.start()

        def _sig_handler(signo, frame) -> None:
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

        self._dispatcher_broker.mqtt_publish(f'{AGENT}/state', 'running', retain=True)

        active_start_count = active_count()
        while self.RUNNING:
            if not self.update_queue.empty():
                if active_count() - active_start_count < self._thread_count:
                    worker = Thread(target=handle_updates, args=(self,))
                    worker.setDaemon(True)
                    worker.start()
            sleep(1)

        self._dispatcher_broker.mqtt_publish(f'{AGENT}/state', 'dead', retain=True)
        self._dispatcher_broker.stop()

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
                    validated_package_list = parse_and_validate_package_list(self._package_list)
                    if validated_package_list is None:
                        raise DispatcherException(
                            F'parsing and validating package list: {self._package_list} failed')
                    SotaOsFactory(self._dispatcher_broker, self._sota_repos, validated_package_list).\
                        get_os(detected_os).\
                        create_snapshotter('update',
                                           snap_num='1',
                                           proceed_without_rollback=True,
                                           reboot_device=True).commit()
                except OSError:
                    # harmless here--mender commit is speculative
                    pass
        self.create_workload_orchestration_instance()
        self.invoke_workload_orchestration_check(True)

    def _do_config_operation(self, parsed_head: XmlHandler) -> Result:
        """Performs either a config load or update of config items.  Delegates to either
        do_config_install_update_config_items or do_config_install_load method depending on type
        of operation invoked

        @param parsed_head: The root parsed xml. It determines config_cmd_type
        @return (dict): returns success or failure dict from child methods
        """
        config_cmd_type, value_object = self._config_operation._get_config_value(parsed_head)
        if config_cmd_type == 'load':
            return self._config_operation._do_config_install_load(parsed_head=parsed_head)
        else:
            return self._config_operation._do_config_install_update_config_items(config_cmd_type, value_object)

    def _perform_cmd_type_operation(self, parsed_head: XmlHandler, xml: str) -> Result:
        """Performs either a reboot or shutdown or decommission based on type
        of command sent.

        @param parsed_head: The root parsed xml. It determines cmd type
        @return (dict): returns success or failure dict from child methods
        """
        cmd = parsed_head.get_element('cmd')

        if cmd == "shutdown":
            message = self.device_manager.shutdown()
        elif cmd == "restart":
            logger.info("Restart command received.  Restarting system...")
            message = self.device_manager.restart()
            if message == SUCCESS_RESTART:
                state: dispatcher_state.DispatcherState = {'restart_reason': 'restart_cmd'}
                dispatcher_state.write_dispatcher_state_to_state_file(state)
        elif cmd == "query":
            self._dispatcher_broker.mqtt_publish(QUERY_CMD_CHANNEL, xml)
            return PUBLISH_SUCCESS
        elif cmd == "custom":
            header = parsed_head.get_children('custom')
            json_data = header['data']
            self._dispatcher_broker.mqtt_publish(CUSTOM_CMD_CHANNEL, json_data)
            return PUBLISH_SUCCESS
        elif cmd == "decommission":
            message = self.device_manager.decommission()
        else:
            error = "Unsupported command: " + cmd
            raise DispatcherException(error)
        return Result(CODE_OK, message)

    def _telemetry(self, message: str) -> None:
        self._dispatcher_broker.telemetry(message)

    def _send_result(self, message: str, id: str = "") -> None:
        """Sends result message to local MQTT channel

        If id is specified, the message is sent to RESPONSE_CHANNEL/id instead of RESPONSE_CHANNEL

        Raises ValueError if id contains a slash

        @param message: message to be published to cloud
        """
        self._dispatcher_broker.send_result(message, id)

    def do_install(self, xml: str, schema_location: Optional[str] = None) -> Result:
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
            elif type_of_manifest == 'source':
                logger.debug('Running source command')
                # FIXME: actually detect OS
                result = do_source_command(
                    parsed_head, source.constants.OsType.Ubuntu, self._dispatcher_broker)
            elif type_of_manifest == 'ota':
                # Parse manifest
                header = parsed_head.get_children('ota/header')
                ota_type = header['type']
                repo_type = header['repo']
                resource = parsed_head.get_children(f'ota/type/{ota_type}')
                kwargs = {'ota_type': ota_type}

                # Record OTA data for logging.
                self._update_logger.set_time()
                self._update_logger.ota_type = ota_type
                self._update_logger.metadata = xml

                if ota_type == OtaType.POTA.name.lower():
                    ota_list = create_ota_resource_list(parsed_head, resource)
                    # Perform manifest checking first before OTA
                    self._validate_pota_manifest(
                        repo_type, kwargs, parsed_head, ota_list)

                    for ota in sorted(ota_list.keys()):
                        kwargs['ota_type'] = ota
                        result = self._do_ota_update(
                            ota, repo_type, ota_list[ota], kwargs, parsed_head)
                        if result == Result(CODE_BAD_REQUEST, "FAILED TO INSTALL") or result == OTA_FAILURE:
                            break
                else:
                    result = self._do_ota_update(
                        ota_type, repo_type, resource, kwargs, parsed_head)

            elif type_of_manifest == 'config':
                logger.debug('Running configuration command sent down ')
                result = self._do_config_operation(parsed_head)
        except (DispatcherException, UrlSecurityException) as error:
            logger.error(error)
            result = Result(CODE_BAD_REQUEST, f'Error during install: {error}')
            self._update_logger.status = FAIL
            self._update_logger.error = str(error)
        except SourceError as error:
            logger.error(error)
            result = Result(CODE_BAD_REQUEST, f'Error changing sources files: {error}')
            self._update_logger.status = FAIL
            self._update_logger.error = str(error)
        except XmlException as error:
            result = Result(CODE_MULTIPLE, f'Error parsing/validating manifest: {error}')
            self._update_logger.status = FAIL
            self._update_logger.error = str(error)
        except (AotaError, FotaError, SotaError) as e:
            result = Result(CODE_BAD_REQUEST, str(e))
            self._update_logger.status = FAIL
            self._update_logger.error = str(e)
        finally:
            logger.info('Install result: %s', str(result))
            self._send_result(str(result))
            if result.status != CODE_OK and parsed_head:
                self._update_logger.status = FAIL
                self._update_logger.error = str(result)
                self.invoke_workload_orchestration_check(True, type_of_manifest, parsed_head)

            # FOTA, SOTA and POTA will be in PENDING state before system reboot.
            if result.status == CODE_OK and \
                    self._update_logger.ota_type != "sota" and \
                    self._update_logger.ota_type != "fota" and \
                    self._update_logger.ota_type != "pota":
                self._update_logger.status = OTA_SUCCESS
                self._update_logger.error = ""
            self._update_logger.save_log()
            return result

    def _do_ota_update(self, ota_type: str, repo_type: str, resource: dict,
                       kwargs: dict, parsed_head: XmlHandler) -> Result:
        """Performs OTA updates by creating a thread based on OTA factory detected from the manifest

        @param ota_type: Type of OTA requested (AOTA/FOTA/SOTA)
        @param repo_type: Type of repo to fetch files (local/remote)
        @param resource: resource to parse
        @param kwargs: arguments dictionary to be updated after parsing resources
        @param parsed_head: Parsed head of the manifest xml
        @return Result: PUBLISH_SUCCESS if success
        """
        logger.debug("")
        factory = OtaFactory.get_factory(
            ota_type.upper(),
            repo_type,
            self._dispatcher_broker,
            self.proceed_without_rollback,
            self._sota_repos,
            self._install_check_service,
            self._update_logger,
            self.config_dbs)

        p = factory.create_parser()
        # NOTE: p.parse can raise one of the *otaError exceptions
        parsed_manifest = p.parse(resource, kwargs, parsed_head)
        self.check_username_password(parsed_manifest)

        t = factory.create_thread(parsed_manifest)
        return t.start()

    def _validate_pota_manifest(self, repo_type: str,
                                kwargs: dict, parsed_head: XmlHandler, ota_list: dict) -> None:
        """Validate POTA manifest by checking FOTA and SOTA information before starting OTA.

        @param repo_type: Type of repo to fetch files (local/remote)
        @param kwargs: arguments dictionary to be updated after parsing resources
        @param parsed_head: Parsed head of the manifest xml
        """
        for ota in sorted(ota_list.keys()):
            logger.debug(f"ota = {ota}")
            logger.debug("")
            factory = OtaFactory.get_factory(
                ota.upper(),
                repo_type,
                self._dispatcher_broker,
                self.proceed_without_rollback,
                self._sota_repos,
                self._install_check_service,
                self._update_logger,
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

    def _on_cloud_request(self, topic: str, payload: str, qos: int) -> None:
        """Called when a message is received from cloud

        @param topic: incoming topic
        @param payload: incoming payload
        @param qos: quality of service level
        """
        logger.info('Cloud request received: %s on topic: %s',
                    mask_security_info(payload), topic)
        request_type = topic.split('/')[2]
        request_id = topic.split('/')[3] if len(topic.split('/')) > 3 else None
        manifest = payload
        if not self.update_queue.full():
            self.update_queue.put((request_type, manifest, request_id))
        else:
            self._send_result(
                str(Result(CODE_FOUND, "OTA In Progress, Try Later")))

    def _on_message(self, topic: str, payload: Any, qos: int) -> None:
        """Called when a message is received from _telemetry-agent

        @param topic: incoming topic
        @param payload: incoming payload
        @param qos: quality of service level
        """
        logger.info('Message received: %s on topic: %s', payload, topic)

    def _initialize_broker(self) -> None:
        """Set up initial subscription topics. The callbacks have following purposes:

        a.) _on_message : called when a message is received from _telemetry agent
        b.) _on_cloud_request: called when a message is received from cloud
        c.) override_defaults: called when config agent sends updates value
        """

        def override_defaults(topic: str, payload: Any, qos: int) -> None:
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

        try:
            logger.debug('Subscribing to: %s', STATE_CHANNEL)
            self._dispatcher_broker.mqtt_subscribe(STATE_CHANNEL, self._on_message)

            logger.debug('Subscribing to: %s', CONFIGURATION_DISPATCHER_UPDATE_CHANNEL)
            self._dispatcher_broker.mqtt_subscribe(
                CONFIGURATION_DISPATCHER_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', CONFIGURATION_SOTA_UPDATE_CHANNEL)
            self._dispatcher_broker.mqtt_subscribe(
                CONFIGURATION_SOTA_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', CONFIGURATION_ALL_AGENTS_UPDATE_CHANNEL)
            self._dispatcher_broker.mqtt_subscribe(
                CONFIGURATION_ALL_AGENTS_UPDATE_CHANNEL, override_defaults)

            logger.debug('Subscribing to: %s', TC_REQUEST_CHANNEL)
            self._dispatcher_broker.mqtt_subscribe(TC_REQUEST_CHANNEL, self._on_cloud_request)

        except Exception as exception:
            logger.exception('Subscribe failed: %s', exception)

    def invoke_sota(self, snapshot: Optional[Any] = None, action: Optional[Any] = None) -> None:
        """Invokes SOTA in either snapshot_revert or snapshot_delete mode along with snapshot_num

        @param kwargs: dict value containing action='snapshot_revert' or 'snapshot_delete',
        snapshot_num
        """
        logger.debug('Invoking SOTA')

        parsed_manifest = {'sota_mode': self.sota_mode, 'package_list': self._package_list,
                           'sota_cmd': 'rollback', 'log_to_file': None,
                           'sota_repos': self._sota_repos,
                           'uri': None, 'signature': None, 'hash_algorithm': None,
                           'username': None, 'password': None, 'release_date': None, "deviceReboot": "yes"}
        sota_instance = SOTA(parsed_manifest,
                             REMOTE_SOURCE,
                             self._dispatcher_broker,
                             self._update_logger,
                             self._sota_repos,
                             self._install_check_service,
                             snapshot, action)

        sota_instance.execute(self.proceed_without_rollback)

    def create_workload_orchestration_instance(self) -> None:
        """This method used to create WorkloadOrchestration instance.
        """
        self._wo = WorkloadOrchestration(self._dispatcher_broker)

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

    def check_sota_state(self) -> None:
        """If the restart reason is SOTA then it waits for diag agent to respond with health report. If the wait
        times-outs or in case of bad health report, it performs a SOTA rollback
        In case of a good health report, it just deletes the snapshot."""
        try:
            self._install_check_service.install_check(check_type='swCheck', size=0)
            self._install_check_service.install_check(check_type='check_network', size=0)
            self._telemetry('On Boot, Diagnostics reports healthy system')
            logger.info("On Boot, Diagnostics reports healthy system")
            self.invoke_sota(action='diagnostic_system_healthy', snapshot=None)
            self._update_logger.update_log(OTA_SUCCESS)
            logger.info(OTA_SUCCESS)
        except DispatcherException:
            self._telemetry(
                'On Boot, Diagnostics reports some services not up after previous SOTA')
            self.invoke_sota(action='diagnostic_system_unhealthy', snapshot=None)
            self._update_logger.update_log(FAIL)
            logger.info(FAIL)

    def check_fota_state(self, fota_state: dispatcher_state.DispatcherState) -> None:
        """This method checks the FOTA info in dispatcher state file and validates the release date
        and bios version number within the file to match the device's fw info and sends the _telemetry
        info accordingly based on the validation of information above.

        @params fota_state: The consumed information from the dispatcher state file.
        """
        # If all the checks pass, the OTA status changes to SUCCESS at the end.
        self._update_logger.update_log(FAIL)

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
            self._update_logger.update_log(OTA_SUCCESS)
        else:
            self._send_result("FAILED INSTALL: Overall FOTA update failed. Firmware not updated.")

    def check_dispatcher_state_info(self) -> None:
        """This method is always called on restarting dispatcher.  If there is a dispatcher state
        file existing, then it checks for the restart reason.
        If the restart reason is SOTA, check_sota_state function continues
        If the restart reason is FOTA, check_fota_state function continues
        If the restart reason is POTA, both SOTA and FOTA info is checked.
        """

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
                self.check_fota_state(state)
            elif OtaType.POTA.name.lower() in restart_reason:
                self.check_fota_state(state)
                self.check_sota_state()
            elif 'restart' in restart_reason:
                self._send_result("Reboot SUCCESSFUL.")
            else:
                self.check_sota_state()

            dispatcher_state.clear_dispatcher_state()
        else:
            self._telemetry('Dispatcher detects normal boot sequence')


def handle_updates(dispatcher: Any,
                   schedule_manifest_schema=SCHEDULE_SCHEMA_LOCATION,
                   manifest_schema=SCHEMA_LOCATION) -> None:
    """Global function to handle multiple requests from cloud using a FIFO queue.

    @param dispatcher: callback to dispatcher
    """
    message: Tuple[str, str, Optional[str]] = dispatcher.update_queue.get()
    request_type: str = message[0]
    manifest: str = message[1]
    if message[2]:
        request_id: str = message[2]

    if request_type == "schedule":
        if not request_id:
            dispatcher._send_result("Error: No request ID provided for schedule request.")

        logger.debug("DEBUG: manifest = " + manifest)
        try:
            schedule = ScheduleManifestParser(manifest, schedule_manifest_schema, manifest_schema)
        except XmlException as e:
            logger.error("XMLException parsing schedule: " + str(e))
            dispatcher._send_result(f"Error parsing schedule manifest: {str(e)}", request_id)
            return

        # Clear the database of existing schedules before we add the new schedules
        with sql_lock:
            dispatcher.sqlite_mgr.clear_database()
        # Remove all the jobs in apscheduler.
        dispatcher.ap_scheduler.remove_all_jobs()

        # Add schedules to the database
        if schedule.single_scheduled_requests or schedule.repeated_scheduled_requests:
            def process_scheduled_requests(scheduled_requests: Sequence[Schedule]):
                with sql_lock:
                    for requests in scheduled_requests:
                        dispatcher.sqlite_mgr.create_schedule(requests)
            all_scheduled_requests = schedule.single_scheduled_requests + schedule.repeated_scheduled_requests
            process_scheduled_requests(all_scheduled_requests)

        # Add job to the scheduler
        single_schedules = dispatcher.sqlite_mgr.get_all_single_schedules_in_priority_order()
        logger.info(f"Total single scheduled tasks: {len(single_schedules)}")
        for single_schedule in single_schedules:
            dispatcher.ap_scheduler.add_single_schedule_job(dispatcher.do_install, single_schedule)
            logger.debug(f"Scheduled single job: {single_schedule}")

        repeated_schedules = dispatcher.sqlite_mgr.get_all_repeated_schedules_in_priority_order()
        logger.info(f"Total repeated scheduled jobs: {len(repeated_schedules)}")
        for repeated_schedule in repeated_schedules:
            dispatcher.ap_scheduler.add_repeated_schedule_job(
                dispatcher.do_install, repeated_schedule)
            logger.debug(f"Scheduled repeated job: {repeated_schedule}")

        for imm in schedule.immedate_requests:
            for manifest in imm.manifests:
                try:
                    dispatcher.do_install(xml=manifest)
                except (NotImplementedError, DispatcherException) as e:
                    dispatcher._send_result(str(e), request_id)
        dispatcher._send_result("", request_id)
        return

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
