"""
    Central data handler service for vision-agent manageability framework.
    - Handle incoming MQTT and xlink message
    - Create appropriate command and add it to Invoker
    - Trigger an OTA update

    @copyright: Copyright 2019-2022 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""

import logging
import os
from typing import List, Optional, Any, Dict
from threading import Lock

import vision
import inbm_vision_lib
import vision.data_handler
import vision.manifest_parser
import vision.validater
import vision.configuration_constant

from inbm_common_lib.validater import configuration_bounds_check
from inbm_common_lib.utility import validate_file_type, get_canonical_representation_of_path, remove_file, \
    remove_file_list
from inbm_common_lib.utility import clean_input
from inbm_common_lib.constants import CONFIG_LOAD
from inbm_vision_lib.constants import NODE, NODE_CLIENT, CONFIG_GET, CONFIG_SET, TBH, \
    FOTA, SOTA, POTA, VISION, SecurityException, XmlException, create_success_message, LIB_FIRMWARE_PATH
from inbm_vision_lib.invoker import Invoker
from ..rollback_manager import RollbackManager

from .request_data_handler import GeneralDataHandler, get_dh_factory
from .query import _create_query_response, _create_query_guid_response

from ..command import configuration_command, ota_command, command, broker_command
from ..constant import INVOKER_QUEUE_SIZE, AGENT, CONFIG_LOCATION, \
    NO_ACTIVE_NODES_FOUND_ERROR, RESTART_TIMER_SECS, VISION_ID, VisionException, SUCCESS, MAX_CONFIG_LOAD_TIMER_SECS, \
    XLINK_PROVISION_PATH
from ..parser import XLinkParser
from ..status_watcher import StatusWatcher
from ..updater import Updater, ConfigurationLoader, get_updater_factory

logger = logging.getLogger(__name__)


class DataHandler(vision.data_handler.idata_handler.IDataHandler):
    # docstring inherited
    flashless_filepath = vision.configuration_constant.DEFAULT_FLASHLESS_FILE_PATH
    max_fota_update_wait_time = vision.configuration_constant.CONFIG_FOTA_COMPLETION_TIMER_SECS.default_value
    max_sota_update_wait_time = vision.configuration_constant.CONFIG_SOTA_COMPLETION_TIMER_SECS.default_value
    max_pota_update_wait_time = vision.configuration_constant.CONFIG_POTA_COMPLETION_TIMER_SECS.default_value

    def __init__(self, vision_callback: vision.ivision.IVision,
                 config_callback: inbm_vision_lib.configuration_manager.ConfigurationManager) -> None:
        """Acts as the Client in the Command Design Pattern

        @param vision_callback: Callback to the Node object
        @param config_callback: Callback to Configuration object
        """

        self._vision_callback = vision_callback
        self._mqtt_queue: List[str] = []
        self._xlink_queue: List[str] = []
        self._registry_manager = vision.registry_manager.RegistryManager(self)
        self._invoker = Invoker(INVOKER_QUEUE_SIZE)
        self._node_heartbeat_interval_secs = \
            vision.configuration_constant.CONFIG_HEARTBEAT_TRANSMISSION_INTERVAL_SECS.default_value
        self._updater: Optional[Updater] = None
        self._status_watcher: Optional[StatusWatcher] = None
        self._config = config_callback
        self._flashless_rollback: Optional[RollbackManager] = None
        self.load_config_file(True)
        self._running = True
        self.boot_device_lock = Lock()

    def load_config_file(self, is_startup: bool = False) -> None:
        """Load the config value from config file.

        @param is_startup: True if loading the file during initialization.  Used to ensure we don't send a telemetry
        response for the configuration load during initialization.
        """

        logger.debug("Load values from {0}".format(CONFIG_LOCATION))
        try:
            all_keys = self._config.get_children(AGENT)
            if all_keys:
                for key in all_keys:
                    set_request = "{0}:{1}".format(key, all_keys[key])
                    self.manage_configuration_update(set_request)
                message = inbm_vision_lib.constants.create_success_message(
                    'Configuration command: SUCCESSFUL')
            else:
                message = inbm_vision_lib.constants.create_error_message(
                    'Configuration command: FAILED. No keys found in config file.')
        except inbm_vision_lib.configuration_manager.ConfigurationException as error:
            message = inbm_vision_lib.constants.create_error_message(
                'Configuration command: FAILED with error: {}'.format(error))
        finally:
            if not is_startup:
                # Only send back response from a cloud request.  Not during initialization.
                self.send_telemetry_response(VISION_ID, message)

    def send_node_register_response(self, node_id) -> None:
        """Create and send registration confirmation command with heartbeat interval(s) to node

        @param node_id: device id of targeted node
        """
        logger.debug(
            'Create register response for %s with heartbeat interval %i seconds.', node_id,
            self._node_heartbeat_interval_secs)
        message = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<message>'
                   '    <registerResponse id="{}">'
                   '        <heartbeatIntervalSecs>{}</heartbeatIntervalSecs>'
                   '    </registerResponse>'
                   '</message>').format(
            clean_input(node_id),
            self._node_heartbeat_interval_secs
        )
        c = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), message)
        self._invoker.add(c)

    def send_file(self, node_id: str, file_path: str) -> None:
        """Create send OTA file command with filename to node

        @param node_id: a string contains device id of targeted node agent
        @param file_path: a string contains location of file to be sent
        """
        logger.debug('Send OTA file to device %s.', node_id)
        cmd = ota_command.SendFileCommand(
            node_id, self._vision_callback.get_node_connector(), file_path)
        self._invoker.add(cmd)
        tele_cmd = broker_command.SendTelemetryEventCommand(
            node_id, self._vision_callback.get_broker(), "Sending file to {0}...".format(node_id))
        self._invoker.add(tele_cmd)

    def send_ota_manifest(self, node_id: str, manifest: str) -> None:
        """Create send ota manifest command with revised manifest to node

        @param node_id: a string contains device id of targeted node agent
        @param manifest: a revised manifest to be sent to node
        """
        logger.debug('Send OTA manifest to device %s.', node_id)
        revised_manifest = ('<?xml version="1.0" encoding="utf-8"?>'
                            '<message>'
                            '    <otaUpdate id="{0}">'
                            '        <items>'
                            '{1}'
                            '        </items>'
                            '    </otaUpdate>'
                            '</message>'
                            ).format(
            clean_input(node_id),
            manifest
        )
        cmd = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), revised_manifest)
        self._invoker.add(cmd)

    def send_config_load_manifest(self, node_id: str, manifest: str, target_type: str) -> None:
        """Create send node configuration load manifest command with revised manifest to node

        @param node_id: a string contains device id of targeted node agent
        @param manifest: a revised manifest to be sent to node
        @param target_type: target type of the load config request, either node or node_client
        """
        logger.debug(f'Send load configuration manifest to device {node_id}.')
        cmd = configuration_command.SendNodeConfigurationLoadManifestCommand(
            node_id, self._vision_callback.get_node_connector(), manifest, target_type)
        self._invoker.add(cmd)

    def send_reregister_request(self, node_id: str) -> None:
        """Create and send reregister request message to node

        @param node_id: a string contains device id of targeted node agent
        """
        logger.debug(f'Send Reregister request to node {node_id}.')
        message = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<message>'
                   '    <reregister id="{}"/>'
                   '</message>').format(clean_input(node_id))
        cmd = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), message)
        self._invoker.add(cmd)

    def create_telemetry_event(self, node_id: str, message: str) -> None:
        """Create send telemetry event command that will send the message through broker

        @param node_id: a string contains device id of targeted node agent
        @param message: message to be sent via broker
        """
        cmd = broker_command.SendTelemetryEventCommand(
            node_id, self._vision_callback.get_broker(), message)
        self._invoker.add(cmd)

    def send_telemetry_response(self, node_id: str, message: Dict[str, str]) -> None:
        """Create send telemetry response command that will send the message through broker

        @param node_id: a string contains device id of targeted node agent
        @param message: message to be sent via broker
        """
        cmd = broker_command.SendTelemetryResponseCommand(
            node_id, self._vision_callback.get_broker(), message)
        self._invoker.add(cmd)

    def create_download_request(self, node_id: str, file_size: int) -> None:
        """Create send download request message with file size to node

        @param node_id: a string contains device id of targeted node agent
        @param file_size: integer representing file size in kb
        """
        message = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<message>'
                   '    <requestToDownload id="{}">'
                   '        <items>'
                   '            <size_kb>{}</size_kb>'
                   '        </items>'
                   '    </requestToDownload>'
                   '</message>').format(
            clean_input(node_id),
            file_size
        )
        cmd = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), message)
        self._invoker.add(cmd)

    def boot_device(self, sw_device_id: str) -> None:
        """Create send download request command with file size to be sent to node

        @param sw_device_id: sw device id of targeted node agent
        """
        if self._config.get_element([vision.configuration_constant.BOOT_FLASHLESS_DEV], AGENT)[0] == "true":
            while self._running and self.boot_device_lock.acquire():
                # The lock will be released once the BootDeviceCommand complete.
                cmd = command.BootDeviceCommand(
                    sw_device_id, self._vision_callback.get_node_connector(), self._vision_callback.get_broker(),
                    self.boot_device_lock)
                self._invoker.add(cmd)
                break
        else:
            logger.debug("Flashless boot device disabled. Vision Agent won't boot the device.")

    def _check_if_request_allowed(self) -> None:
        if self._updater:
            raise VisionException(
                f"An update is currently in progress. Please try again after "
                f"{self._updater.get_remaining_time()} seconds.")
        if self._status_watcher:
            raise VisionException(f"A restart is in progress.  Please try again after "
                                  f"{self._status_watcher.get_remaining_time()} seconds.")
        if self._flashless_rollback:
            raise VisionException(
                f"A flashless update is currently in progress. Please try again after "
                f"{self._flashless_rollback.get_remaining_time()} seconds.")

    def receive_restart_request(self, payload: str) -> None:
        # docstring inherited
        try:
            parsed_manifest = vision.manifest_parser.parse_manifest(payload)

            self._check_if_request_allowed()

            n = GeneralDataHandler(self._registry_manager, {}, parsed_manifest.targets)
            targets = n.get_validated_nodes()

            self._status_watcher = StatusWatcher(targets, self, RESTART_TIMER_SECS)
            for t in targets:
                if not t.hardware.is_flashless:
                    cmd = command.SendRestartNodeCommand(
                        t.device_id, self._vision_callback.get_node_connector())
                    self._invoker.add(cmd)
        except VisionException as error:
            err_msg = inbm_vision_lib.constants.create_error_message(str(error))
            self.send_telemetry_response(VISION_ID, err_msg)

    def receive_mqtt_message(self, payload: str) -> None:
        # docstring inherited
        logger.debug('Received payload.')
        try:
            parsed_manifest = None
            parsed_manifest = vision.manifest_parser.parse_manifest(payload)
            logger.debug(f'Manifest type: %s', str(parsed_manifest.manifest_type))
            logger.debug('Number of targets: %i', len(parsed_manifest.targets))
            self._check_if_request_allowed()

            node_list = list(filter(lambda a: a != 'None', parsed_manifest.targets))

            request_dh = get_dh_factory(parsed_manifest.manifest_type, self._registry_manager,
                                        parsed_manifest.info, node_list)
            valid_target_ids = request_dh.get_validated_node_ids()

            # Send the number of target to be updated. INBC will use this information.
            self.send_telemetry_response(
                VISION_ID, create_success_message(f'OTA_TARGETS:{len(valid_target_ids)}'))

            if not valid_target_ids:
                raise VisionException(NO_ACTIVE_NODES_FOUND_ERROR + "OTA update failed.")

            valid_target_ids, flashless_target_ids = vision.flashless_utility.filter_flashless_device(
                valid_target_ids, self._registry_manager)
            file_paths = inbm_vision_lib.utility.build_file_path_list(parsed_manifest.info)

            if not file_paths:
                raise VisionException('Missing files for OTA update')

            try:
                validate_file_type(file_paths)
            except TypeError as error:
                raise VisionException(f"OTA FAILURE due to {error}")

            ota_timer = self.max_fota_update_wait_time if parsed_manifest.manifest_type == FOTA \
                else self.max_sota_update_wait_time \
                if parsed_manifest.manifest_type == SOTA else self.max_pota_update_wait_time
            self._updater = get_updater_factory(parsed_manifest.manifest_type, valid_target_ids, self, file_paths,
                                                parsed_manifest.info, ota_timer)
            cmd = ota_command.UpdateNodeCommand(self._updater)
            self._invoker.add(cmd)

            if flashless_target_ids:
                try:
                    vision.flashless_utility.copy_backup_flashless_files()
                    if parsed_manifest.manifest_type == POTA:
                        inbm_vision_lib.utility.move_flashless_files(parsed_manifest.info['fota_path'],
                                                                     self.flashless_filepath)
                    else:
                        inbm_vision_lib.utility.move_flashless_files(parsed_manifest.info['path'],
                                                                     self.flashless_filepath)

                except (FileNotFoundError, OSError) as error:
                    # If error happened, reset updater.
                    self._updater.updater_timer.stop()
                    self._updater = None
                    vision.flashless_utility.rollback_flashless_files()
                    # After copied back the backup files, remove the files in backup folder.
                    vision.flashless_utility.remove_backup_files()
                    raise VisionException(error)

                for target_id in flashless_target_ids:
                    # Reset each flashless device by providing the node id. Once reset completed, vision will receive
                    # reset notification. After received notification, it calls boot command to boot up the device.
                    self.reset_device(target_id)
                    # Initialize rollback manager to rollback the image if flashless update failed
                self._flashless_rollback = RollbackManager(node_list=flashless_target_ids,
                                                           config=self._config,
                                                           node_connector=self._vision_callback.get_node_connector(),
                                                           broker=self._vision_callback.get_broker())

        except (VisionException, XmlException, OSError, UnboundLocalError, FileNotFoundError, TypeError) as error:
            ota_file_path = inbm_vision_lib.utility.get_file_path_from_manifest(payload)
            if parsed_manifest:
                remove_file_list(
                    inbm_vision_lib.utility.build_file_path_list(parsed_manifest.info))
            else:
                remove_file(ota_file_path)
            err_msg = inbm_vision_lib.constants.create_error_message(
                "OTA FAILURE: " + str(error))
            logger.error(err_msg)
            self.send_telemetry_response(VISION_ID, err_msg)

    def manage_configuration_request(self, message: str) -> None:
        # docstring inherited
        cmd = None  # type: Any
        try:
            parsed_manifest = vision.manifest_parser.TargetParsedManifest.from_instance(
                vision.manifest_parser.parse_manifest(message))

            # Node config request
            if parsed_manifest.target_type == NODE or parsed_manifest.target_type == NODE_CLIENT:
                self._check_if_request_allowed()
                c = GeneralDataHandler(self._registry_manager, {}, parsed_manifest.targets)
                targets = c.get_validated_node_ids()

                cmd = self._handle_node_configuration_request(vision.manifest_parser.TargetParsedManifest(
                    parsed_manifest.manifest_type,
                    parsed_manifest.info, targets,
                    parsed_manifest.target_type))
            else:
                # Validate key before sending response
                vision.validater.validate_key(parsed_manifest.info['path'])
                # vision-agent config request
                cmd = self._handle_vision_configuration_request(parsed_manifest)
        except (XmlException, VisionException, TypeError, PermissionError) as error:
            file_path = inbm_vision_lib.utility.get_file_path_from_manifest(message)
            remove_file(file_path)
            err_msg = inbm_vision_lib.constants.create_error_message(
                "Configuration command: FAILED with error: {0}".format(str(error)))
            logger.error(f'{err_msg}')
            cmd = broker_command.SendTelemetryResponseCommand(
                VISION_ID, self._vision_callback.get_broker(), err_msg)

        finally:
            logger.debug(f"Sending command: {cmd}")
            if cmd:
                self._invoker.add(cmd)

    def _handle_node_configuration_request(self,
                                           parsed_manifest: vision.manifest_parser.TargetParsedManifest) \
            -> command.Command:
        """Handle the node config request received from OTA Client.

        @param parsed_manifest: parsed fields from manifest
        @return: Command object
        """
        logger.debug(f"manifest_type:{parsed_manifest.manifest_type} paths:{parsed_manifest.info['path']} "
                     f"targets:{parsed_manifest.targets}")
        paths = parsed_manifest.info['path'].split(";")
        if parsed_manifest.manifest_type == "load":
            if self._updater:
                raise VisionException(
                    "Only one update is allowed at a time. Please try again after {0} seconds.".format(
                        self._updater.get_remaining_time()))
            manifest = {'path': parsed_manifest.info['path']}
            validate_file_type(paths)

            self._updater = ConfigurationLoader(
                parsed_manifest.targets, self, paths, manifest, MAX_CONFIG_LOAD_TIMER_SECS,
                parsed_manifest.target_type)
            return ota_command.UpdateNodeCommand(self._updater)
        else:
            return configuration_command.SendNodeConfigValueCommand(
                self._vision_callback.get_node_connector(),
                self._registry_manager, paths, parsed_manifest.manifest_type, parsed_manifest.targets,
                parsed_manifest.target_type)

    def _handle_vision_configuration_request(self, parsed_manifest: vision.manifest_parser.TargetParsedManifest) \
            -> Optional[command.Command]:
        """Handle the vision config request received from OTA Client.

        @param parsed_manifest: parsed fields from manifest
        @raises VisionException
        """
        value_list = parsed_manifest.info['path'].split(";")
        logger.debug("value_list is %s", value_list)
        if parsed_manifest.manifest_type == CONFIG_GET:
            return configuration_command.GetVisionConfigValuesCommand(
                VISION_ID, self._vision_callback.get_broker(), value_list, self._config,
                parsed_manifest.target_type)
        elif parsed_manifest.manifest_type == CONFIG_SET:
            return configuration_command.SetVisionConfigValuesCommand(
                VISION_ID, self._vision_callback.get_broker(), value_list, self._config,
                parsed_manifest.target_type)
        elif parsed_manifest.manifest_type == CONFIG_LOAD:
            path = value_list[0]
            validate_file_type([path])
            return configuration_command.LoadConfigFileCommand(
                VISION_ID, self._vision_callback.get_broker(), path, self._config, parsed_manifest.manifest_type)
        raise VisionException(
            "Unsupported config command - {}".format(parsed_manifest.manifest_type))

    def manage_configuration_update(self, element_key: str) -> None:
        # docstring inherited
        logger.debug(element_key)
        key_value = element_key.split(":", 1)
        key = key_value[0]

        if key not in vision.configuration_constant.KEY_MANIFEST:
            raise VisionException("Attempt to update invalid configuration key")

        if key == vision.configuration_constant.FLASHLESS_FILE_PATH:
            self.flashless_filepath = key_value[1]

        # Update component based on new value in key_value[1]
        if key in vision.configuration_constant.INT_CONFIG_VALUES:
            if not key_value[1].isdigit():
                raise VisionException("Attempt to update integer value with a non-integer value")
            else:
                value = int(key_value[1])
                int_value = int(value)
                self._update_integer_configuration_value(key, int_value)

    def _update_integer_configuration_value(self, key: str, value: int) -> None:
        if key == vision.configuration_constant.VISION_HB_CHECK_INTERVAL_SECS:
            self._registry_manager.update_heartbeat_check_interval(
                configuration_bounds_check(vision.configuration_constant.CONFIG_HEARTBEAT_CHECK_INTERVAL_SECS, value))
        elif key == vision.configuration_constant.NODE_HEARTBEAT_INTERVAL_SECS:
            self._update_heartbeat_transmission_interval(
                configuration_bounds_check(
                    vision.configuration_constant.CONFIG_HEARTBEAT_TRANSMISSION_INTERVAL_SECS, value))
        elif key == vision.configuration_constant.VISION_FOTA_TIMER:
            fv = configuration_bounds_check(
                vision.configuration_constant.CONFIG_FOTA_COMPLETION_TIMER_SECS, value)
            logger.info(f'FOTA update timer changed to {fv}.')
            self.max_fota_update_wait_time = fv
        elif key == vision.configuration_constant.VISION_SOTA_TIMER:
            sv = configuration_bounds_check(
                vision.configuration_constant.CONFIG_SOTA_COMPLETION_TIMER_SECS, value)
            logger.info(f'SOTA update timer changed to {sv}.')
            self.max_sota_update_wait_time = sv
        elif key == vision.configuration_constant.VISION_POTA_TIMER:
            pv = configuration_bounds_check(
                vision.configuration_constant.CONFIG_POTA_COMPLETION_TIMER_SECS, value)
            logger.info(f'POTA update timer changed to {pv}.')
            self.max_pota_update_wait_time = pv
        elif key == vision.configuration_constant.IS_ALIVE_INTERVAL_SECS:
            self._registry_manager.update_is_alive_interval(
                configuration_bounds_check(vision.configuration_constant.CONFIG_IS_ALIVE_TIMER_SECS, value))
        elif key == vision.configuration_constant.VISION_HB_RETRY_LIMIT:
            self._registry_manager.update_heartbeat_retry_limit(
                configuration_bounds_check(vision.configuration_constant.CONFIG_HEARTBEAT_RETRY_LIMIT, value))

    def _update_request_status(self, node_id: str) -> None:
        logger.debug("")
        if self._status_watcher:
            self._status_watcher.set_done(node_id)
            is_done = self._status_watcher.is_all_targets_done()
            if is_done:
                message = inbm_vision_lib.constants.create_success_message(
                    'ALL NODES Restart SUCCESSFUL')
                self.send_telemetry_response(node_id, message)
        if self._updater:
            self._updater.set_done(node_id)
            self._updater.is_all_targets_done()
        if self._flashless_rollback and self._flashless_rollback.is_all_targets_done(node_id):
            # Cancel flashless rollback if all nodes register back to vision as it indicates flashless update success.
            logger.debug('All devices reconnected back. Cancel rollback timer.')
            self._flashless_rollback.stop()
            self._flashless_rollback = None
            self.send_telemetry_response(VISION_ID, create_success_message(
                "FLASHLESS OTA COMMAND SUCCESSFUL"))

    def receive_xlink_message(self, message: str) -> None:
        # docstring inherited
        logger.debug('Received message from xlink.')
        try:
            msg = message.rsplit("::", 1)
            checksum_hash = msg[1]
            actual_msg = msg[0]
            inbm_vision_lib.checksum_validator.validate_message(checksum_hash, actual_msg)
            vision.validater.validate_xlink_message(actual_msg)
            parser = XLinkParser()
            # Key/Value pairs under the items section of the received XML based message
            dictionary: Dict[str, Any]
            cmd, node_id, dictionary = parser.parse(actual_msg)

            c: Optional[command.Command] = None

            if cmd is command.VisionCommands.REGISTER.value:
                self._update_request_status(node_id)
                # Get GUID if node is connected with secure xlink
                guid = None
                is_provisioned = False
                node_connector = self._vision_callback.get_node_connector()
                if node_connector and dictionary['is_xlink_secure']:
                    guid = node_connector.get_guid(node_id)
                    is_provisioned = node_connector.is_provisioned(node_id)
                dictionary.update({"guid": guid})
                dictionary.update({"is_provisioned": is_provisioned})
                c = command.RegisterNodeCommand(node_id, self._registry_manager, dictionary)
            elif cmd is command.VisionCommands.HEARTBEAT.value:
                c = command.UpdateNodeHeartbeatCommand(node_id, self._registry_manager)
            elif cmd is command.VisionCommands.DOWNLOAD_STATUS.value:
                logger.debug('Received download status response from device %s.', node_id)
                c = ota_command.ReceiveDownloadResponseCommand(node_id, self._updater, dictionary)
            elif cmd is command.VisionCommands.SEND_FILE_RESPONSE.value:
                logger.debug('Received send file response from device %s.', node_id)
                logger.debug('%s', str(dictionary))
                c = ota_command.ReceiveRequestDownloadResponse(node_id, self._updater, dictionary)
            elif cmd is command.VisionCommands.OTA_RESULT.value:
                logger.debug('Received otaResult from device %s.', node_id)
                if self._updater and not any(msg in dictionary['result'] for
                                             msg in [str(SUCCESS), "Reboot on hold after Firmware update"]):
                    self._updater.set_target_error(node_id, dictionary['result'])
                c = broker_command.SendTelemetryResponseCommand(node_id, self._vision_callback.get_broker(),
                                                                dictionary)
            elif cmd is command.VisionCommands.TELEMETRY_EVENT.value:
                msg = dictionary.get("telemetryMessage", "")
                c = broker_command.SendTelemetryEventCommand(
                    node_id, self._vision_callback.get_broker(), msg)
            elif cmd is command.VisionCommands.CONFIG_RESPONSE.value:
                logger.debug('Received configResponse from device %s.', node_id)
                if self._updater:
                    if str(SUCCESS) not in dictionary['item']:
                        self._updater.set_target_error(node_id, dictionary['item'])
                    else:
                        self._updater.set_done(node_id)
                        self._updater.is_all_targets_done()

                c = broker_command.SendTelemetryResponseCommand(
                    node_id, self._vision_callback.get_broker(), dictionary)

            if c:
                self._invoker.add(c)
            else:
                logger.error('Unsupported Command received via Xlink')
        except (SecurityException, XmlException, ValueError, KeyError, VisionException) as error:
            error_message = inbm_vision_lib.constants.create_error_message(
                'Error parsing/validating manifest from xlink: {}'.format(error))
            self.send_telemetry_response(VISION_ID, error_message)

    def send_heartbeat_response(self, node_id) -> None:
        """Send heartbeat response message to node after receiving a heartbeat message

        @param node_id: a string contains device id of targeted node agent
        """
        message = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<message>'
                   '    <heartbeatResponse id="{}"/>'
                   '</message>').format(clean_input(node_id))
        c = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), message)
        self._invoker.add(c)

    def send_is_alive(self, node_id) -> None:
        """Send isAlive request message to node when node doesn't response for a long time

        @param node_id: a string contains device id of targeted node agent
        """
        message = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<message>'
                   '    <isAlive id="{}"/>'
                   '</message>').format(clean_input(node_id))
        c = command.SendXlinkMessageCommand(
            node_id, self._vision_callback.get_node_connector(), message)
        self._invoker.add(c)

    def _update_heartbeat_transmission_interval(self, value: int) -> None:
        """Call registry manager to update node heartbeat response interval to new value

        @param value: (int) value obtained from config file
        """
        logger.info('Node heartbeat interval updates from {} to {}.'.format(
            self._node_heartbeat_interval_secs, value))
        self._node_heartbeat_interval_secs = value
        # Send new heartbeat respond time to all node agents
        targets = self._registry_manager.get_target_ids([])
        if targets:
            for node in targets:
                self.send_node_register_response(node)

    def reset_device(self, node_id: str) -> None:
        """Reset device when the device is no longer active.

        @param node_id: node to be reset
        """
        nc = self._vision_callback.get_node_connector()
        rdc = command.ResetDeviceCommand(node_id, nc)
        self._invoker.add(rdc)
        cmd = broker_command.SendTelemetryEventCommand(node_id,  self._vision_callback.get_broker(),
                                                       f"Reset device-{node_id} complete.")
        self._invoker.add(cmd)
        if nc:
            logger.debug(
                f'Actual: {nc.check_platform_type(node_id)} Expected: {TBH}')

    def receive_command_request(self, message: str) -> None:
        try:
            parsed_manifest = vision.manifest_parser.TargetParsedManifest.from_instance(
                vision.manifest_parser.parse_manifest(message))

            # Node query request
            if parsed_manifest.target_type == NODE:
                all_targets = self._registry_manager.get_targets(parsed_manifest.targets)
                if parsed_manifest.info['option'] == 'guid':
                    resp = _create_query_guid_response(self._vision_callback.get_node_connector())
                    files_in_provision_folder = f"Files in {XLINK_PROVISION_PATH}: {os.listdir(XLINK_PROVISION_PATH)}"
                    self.create_telemetry_event(VISION_ID, str(resp))
                    self.create_telemetry_event(VISION_ID, str(files_in_provision_folder))
                elif all_targets:
                    self.create_telemetry_event(
                        VISION_ID, "Number of targets: {0}".format(len(all_targets)))
                    for target in all_targets:
                        resp = _create_query_response(parsed_manifest.info['option'], target)
                        self.create_telemetry_event(target.device_id, str(resp))
                else:
                    self.create_telemetry_event(VISION_ID, "No node registered with vision.")

                self.send_telemetry_response(
                    VISION_ID, inbm_vision_lib.constants.create_success_message("Registry query: SUCCESSFUL"))
            elif parsed_manifest.target_type == VISION:
                if parsed_manifest.info['option'] == "version":
                    self.create_telemetry_event(
                        VISION_ID, "Vision agent version is {0}".format(vision.package_version.get_version()))
                    self.send_telemetry_response(
                        VISION_ID, inbm_vision_lib.constants.create_success_message("Registry query: SUCCESSFUL"))
            else:
                raise VisionException("Unsupported command.")

        except (XmlException, OSError, VisionException) as error:
            self.send_telemetry_response(VISION_ID, inbm_vision_lib.constants.create_error_message(
                "Command {0} FAILED: {1}".format(parsed_manifest.manifest_type, str(error))))

    def publish_xlink_status(self, nid: str, status: str) -> None:
        """Create a command to send the xlink status to the INBC tool

        @param nid: Node ID
        @param status: xlink device status message
        """
        cmd = broker_command.SendXlinkStatusCommand(
            nid, self._vision_callback.get_broker(), status)
        self._invoker.add(cmd)

    def stop(self):
        # docstring inherited
        self._running = False
        self._invoker.stop()
        self._registry_manager.stop()
