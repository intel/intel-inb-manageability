"""
    Workload Orchestration methods called by dispatcher before and after
    any OTA commands having shutdown/reboot.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import json
import logging
import platform
import socket
import time
from typing import Tuple, Dict, Any, Optional
from threading import Thread
from json.decoder import JSONDecodeError
from os import path

import requests
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.count_down_latch import CountDownLatch
from inbm_common_lib.shell_runner import PseudoShellRunner

from .config.config_command import ConfigCommand
from .constants import *
from .dispatcher_callbacks import DispatcherCallbacks
from .dispatcher_exception import DispatcherException

logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class WorkloadOrchestration:
    """Workload Orchestration class to switch device status to schedulable or unschedulable

    @param dispatcher_callbacks: callbacks
    """

    def __init__(self,
                 dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks

    def is_workload_service_file_present(self) -> bool:
        """Checks if workload orchestration files are present.

        @return: return True if present else False; always False if not on Linux
        """
        if platform.system() != 'Linux':
            return False

        file_path = self.get_orchestrator_value(IP)
        return True if file_path and path.exists(file_path) else False

    def is_workload_service_active(self) -> bool:
        """Checks if workload orchestration is active or not.

        @return: return True if service active else False;
        """
        orchestrator_service = self.get_orchestrator_value(ORCHESTRATOR)
        command = f"systemctl is-active {orchestrator_service}"
        (out, err, code) = PseudoShellRunner().run(command)
        if code == 0 and out.strip() == 'active':
            self._dispatcher_callbacks.broker_core.telemetry(
                "Workload Orchestration Service Active")
            return True
        else:
            return False

    def set_workload_orchestration_mode(self, online_mode: bool) -> None:
        """Changes the workload orchestration device status.

        @param online_mode: boolean to indicate device to be online mode
        """
        if self.is_workload_service_file_present():
            if online_mode:
                worker = Thread(target=self._switch_to_online_mode)
                worker.setDaemon(True)
                worker.start()
            elif self.is_workload_service_active():
                self._switch_to_maintenance_mode()

    def _switch_to_maintenance_mode(self) -> None:
        """Changes workload orchestration device status to maintenance mode.
        The result of the rest call along with orchestrator response determine to proceed or not with OTA update.
        """
        try:
            self._dispatcher_callbacks.broker_core.telemetry(
                'Switching Device Workload Orchestration status to Maintenance mode')
            orchestrator_response = self.get_orchestrator_value(ORCHESTRATOR_RESPONSE)
            (return_json, status_code) = self.switch_wo_status("true")
            if status_code != CSL_CMD_STATUS_CODE:
                if orchestrator_response == 'true':
                    raise DispatcherException(
                        "Can't proceed to OTA update ")
                else:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'Failure in switching Device Workload Orchestration status to Maintenance mode')
            elif status_code == CSL_CMD_STATUS_CODE:
                self._process_maintenance_mode_ok_status_result(orchestrator_response, return_json)
        except DispatcherException as e:
            if orchestrator_response == 'true':
                raise DispatcherException(
                    "Failure in switching Device Workload Orchestration status to Maintenance mode: {}".format(str(e)))
            else:
                self._dispatcher_callbacks.broker_core.telemetry(
                    'Failure in switching Device Workload Orchestration status to Maintenance mode: {}'.format(str(e)))

    def _process_maintenance_mode_ok_status_result(self, orchestrator_response: Optional[Any], return_json: Dict) -> None:
        """Checks if workloads are running on the device. If workloads are present, it
        continues to poll until all workloads are shifted.
        It continues to poll thrice if the API request does not go through.
        The API call result along with orchestrator response determine to proceed or not with OTA update.

        @param orchestrator_response: boolean to indicate whether to proceed with OTA update
        @param return_json: Dict of device status mode and workload details
        """
        polling_flag = True
        polling_counter = 0
        if not len(return_json['Workloads']):
            self._dispatcher_callbacks.broker_core.telemetry(
                'Switched Device Workload Orchestration status to Maintenance mode.')
        elif len(return_json['Workloads']):
            self._dispatcher_callbacks.broker_core.telemetry(
                'Workloads present on the Device {}'.format(return_json['Workloads']))
            while polling_flag and len(return_json['Workloads']):
                (return_json, status_code) = self.poll_wo_status()
                if status_code != CSL_POLL_CMD_STATUS_CODE:
                    polling_counter = polling_counter + 1
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'Unable to retrieve Device Workload Orchestration status. Retrying in 10 seconds...')
                    time.sleep(10)
                    if polling_counter == 3:
                        polling_flag = False
                        if orchestrator_response == 'true':
                            raise DispatcherException("Can't proceed to OTA update ")
                        else:
                            self._dispatcher_callbacks.broker_core.telemetry(
                                'Failed to retrieve Device Workload Orchestration status')
                elif status_code == CSL_POLL_CMD_STATUS_CODE:
                    if len(return_json['Workloads']):
                        self._dispatcher_callbacks.broker_core.telemetry(
                            'Switching Device Workload Orchestration status to Maintenance mode: Shifting Workloads {}'.format(return_json['Workloads']))
                    else:
                        self._dispatcher_callbacks.broker_core.telemetry(
                            'Switched Device Workload Orchestration status to Maintenance mode.')
                        break

    def _switch_to_online_mode(self) -> None:
        """Changes device status to online mode in Workload Orchestration Manager.
        Polls the status of the device. If it is in Maintenance mode, it switches to online mode.
        The result of the rest API call determines if it's a success or not.
        """
        try:
            online_flag = True
            timer_flag = True
            while online_flag:
                if timer_flag:
                    timer_flag = False
                else:
                    time.sleep(300)
                if self.is_workload_service_active():
                    online_flag = False
                    (return_json, status_code) = self.poll_wo_status()
                    if status_code != CSL_POLL_CMD_STATUS_CODE:
                        self._dispatcher_callbacks.broker_core.telemetry(
                            'Failed to get Device Workload Orchestration status to verify and switch to online mode')
                    elif status_code == CSL_POLL_CMD_STATUS_CODE:
                        self._process_online_mode_ok_status_result(return_json)
        except DispatcherException as e:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Failure in switching Device workload Orchestration status to Online mode: {}".format(str(e)))

    def _process_online_mode_ok_status_result(self, return_json: Dict) -> None:
        """Checks if the device is in maintenance mode and if it does it calls the API to switch it to online mode.
        The result json determines if the device orchestration status is changed to online mode or not.

        @param return_json: Dict of device status mode and workload details
        """
        if return_json["Enabled"]:
            self._dispatcher_callbacks.broker_core.telemetry(
                'Switching Device Workload Orchestration status to Online mode.')
            (return_json, status_code) = self.switch_wo_status("false")
            if status_code != CSL_CMD_STATUS_CODE:
                self._dispatcher_callbacks.broker_core.telemetry(
                    'Failure in switching Device Workload Orchestration status to Online mode')
            elif status_code == CSL_CMD_STATUS_CODE:
                self._dispatcher_callbacks.broker_core.telemetry(
                    'Switched Device Workload Orchestration status to Online mode')

    def _get_workload_orchestration_file_content(self, file: str) -> str:
        """Reads and returns the workload orchestration file contents

        @return: contents of the file
        """
        try:
            with open(file) as file_content:
                return file_content.read()
        except OSError as e:
            raise DispatcherException(
                f"Could not load workload orchestration config file with error: {e}")

    def get_wo_details(self) -> Tuple[Optional[str], Optional[str]]:
        """Returns workload orchestration details

        @return: device workload orchestration ip and token values
        """
        token = self.get_orchestrator_value(TOKEN)
        ip_port = self.get_orchestrator_value(IP)
        return token, ip_port

    def poll_wo_status(self) -> Tuple[Dict, int]:
        """Create and process the REST API call to poll device workload orchestration status

        @return: API call return status code and json structure 
        """
        (token, ip_port) = self.get_wo_details()

        if token is None or ip_port is None:
            raise DispatcherException(" Workload-Orchestration IP and Token details Not Found")
        try:
            url = self._get_workload_orchestration_file_content(ip_port) + '/api/v1/nodes/' \
                + WorkloadOrchestration.get_hostname() \
                + '/maintenance?token=' + self._get_workload_orchestration_file_content(token)

            result = requests.get(url, verify=self.get_orchestrator_value(CSL_CA))
            return result.json(), result.status_code
        except (TypeError, AttributeError, OSError, ValueError, JSONDecodeError) as e:
            raise DispatcherException(str(e))
        except requests.exceptions.ConnectionError:
            raise DispatcherException(" Request Connection Error")

    def switch_wo_status(self, maintenance_mode: str) -> Tuple[Dict, int]:
        """Create and process the Rest API call to switch device into maintenance/online mode

        @param maintenance_mode: value to change device workload orchestration status
        @return: API call return status code and json structure 
        """
        (token, ip_port) = self.get_wo_details()

        if token is None or ip_port is None:
            raise DispatcherException(" Workload-Orchestration IP and Token details Not Found")
        try:
            url = self._get_workload_orchestration_file_content(ip_port) + '/api/v1/nodes/' \
                + WorkloadOrchestration.get_hostname() \
                + '/maintenance?token=' + self._get_workload_orchestration_file_content(token)

            result = requests.patch(url, data='{"Enabled":' + maintenance_mode + '}', headers={
                "Content-Type": "application/json"}, verify=self.get_orchestrator_value(CSL_CA))
            return result.json(), result.status_code
        except (TypeError, AttributeError, OSError, ValueError, JSONDecodeError) as e:
            raise DispatcherException(str(e))
        except requests.exceptions.ConnectionError:
            raise DispatcherException(" Request Connection Error")

    @staticmethod
    def get_hostname() -> str:
        """Method to return the hostname

        @return: hostname
        """

        return socket.gethostname()

    def get_orchestrator_value(self, child_tag: str) -> Optional[Any]:
        """ This method is used to fetch the Workload-Orchestration details from configuration file using config agent 

        @param child_tag: child tag name whose value needs to be fetched
        @return: Value of the child tag from the configuration file
        """
        latch = CountDownLatch(1)

        def on_command(topic, payload, qos):  # pragma: no cover
            logger.info('Message received: %s on topic: %s', payload, topic)
            try:
                cmd.response = json.loads(payload)

            except ValueError as error:
                logger.error(f'Unable to parse payload: {error}')

            finally:
                # Release lock
                latch.count_down()

        cmd = ConfigCommand('get_element', child_tag)
        # Subscribe to response channel using the same request ID
        self._dispatcher_callbacks.broker_core.mqtt_subscribe(
            cmd.create_response_topic(), on_command)

        # Publish command request
        self._dispatcher_callbacks.broker_core.mqtt_publish(
            cmd.create_request_topic(), cmd.create_payload())
        latch.await_()
        if cmd.response is not None and type(cmd.response) is not dict:
            cmd.response = str(cmd.response).strip().split(':')[1]
            return cmd.response
        else:
            return None
