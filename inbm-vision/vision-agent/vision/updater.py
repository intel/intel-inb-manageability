"""
    Updater class for handling the OTA update

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
from typing import Dict
from typing import List, Optional
from abc import ABC, abstractmethod
from time import sleep

from .constant import CONVERSION_TO_KB, VISION_ID, VisionException
from .request_status import RequestStatus
from .ota_target import OtaTarget
from vision.data_handler.idata_handler import IDataHandler

from inbm_common_lib.utility import get_canonical_representation_of_path, remove_file
from inbm_vision_lib.timer import Timer
from inbm_vision_lib.constants import FOTA, SOTA, POTA, create_error_message, create_success_message

logger = logging.getLogger(__name__)


class Updater(ABC):
    """Manages the requested update

    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: list of files to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @param update_interval: integer representing the waiting time to complete the update
    """

    def __init__(self, target_ids: List[str], data_handler: IDataHandler,
                 file_paths: List[str], manifest: Dict[str, str], update_interval: int, update_type: str) -> None:
        self._data_handler_callback = data_handler
        self._file_paths = file_paths
        self._update_type: str
        self._revised_manifest = self.revise_manifest(manifest)
        self._targets = self._create_target(target_ids)
        self._timer = update_interval
        self._file_size: int
        self.updater_timer = Timer(self._timer, self._updater_timer_expired)
        self.updater_timer.start()
        self._update_type = update_type
        self._file_size = self._get_file_size()
        logger.debug(self._timer)


    @abstractmethod
    def revise_manifest(self, manifest: Dict[str, str]) -> str:
        """Modify manifest to be sent to node

        @param manifest: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        pass

    @abstractmethod
    def update_download_status(self, node_id: str, status: bool) -> None:
        """Call data handler API to send revised manifest to node if file download status is True.
        If the status is False, an error message will be set to otaTarget.

        @param node_id: string representing node device id
        @param status: boolean representing ota file download status
        """
        if status:
            self._set_file_index(node_id, self._get_file_index(node_id) + 1)
            if self._get_file_index(node_id) < len(self._file_paths):
                self.update_download_request_status(node_id, True)
            else:
                logger.debug('Download status of device %s is %s.', node_id, status)
                if self._get_target(node_id):
                    self._update_target_status(node_id, RequestStatus.SendManifest)
                    self._data_handler_callback.send_ota_manifest(node_id, self._revised_manifest)
                else:
                    self._device_not_found(node_id)
        else:
            self._set_error_download_status(node_id)

    def _device_not_found(self, node_id: str) -> None:
        logger.error('Device %s not found.', node_id)
        self.set_target_error(node_id, "Device not found.")

        err_resp = create_error_message(
            f'OTA FAILURE due to download file status: Device {node_id} not found.')
        self._data_handler_callback.send_telemetry_response(node_id, err_resp)

    def _set_error_download_status(self, node_id: str) -> None:
        logger.error('Download status of device %s is False.', node_id)
        if self._get_target(node_id):
            self.set_target_error(node_id, "Download status False")

            err_resp = create_error_message(
                f'OTA FAILURE due to device {node_id} download file status: Fail.')
            self._data_handler_callback.send_telemetry_response(node_id, err_resp)

    def _collect_result(self) -> None:
        """Collect OTA update result of each node and call data handler API to publish the result.

        TODO: There is no variable in OtaTarget to store last message. Can't retrieve the last
        message.
        TODO: Waiting for further update

        """
        for fp in self._file_paths:
            remove_file(fp)

        fail_target = []
        logger.info("Number of Target: %i", len(self._targets))
        logger.info("-------------------------------------------------------------------------")
        if len(self._targets) != 0:
            for index, otaTarget_object in enumerate(self._targets):
                if otaTarget_object.get_error() != "None":
                    fail_target.append(otaTarget_object)
                logger.info("deviceID: %s", otaTarget_object.get_node_id())
                logger.info("error message: %s", otaTarget_object.get_error())
                logger.info("status: %s", otaTarget_object.get_status())
                logger.info(
                    "-------------------------------------------------------------------------")

            # For now, we are just sending an overall successful message when the timer expires.
            if fail_target:
                err_resp = create_error_message(f'{self._update_type} UPDATE Fail.')
                self._data_handler_callback.send_telemetry_response(VISION_ID, err_resp)
            else:
                success_resp = create_success_message(f'{self._update_type} UPDATE SUCCESSFUL')
                self._data_handler_callback.send_telemetry_response(VISION_ID, success_resp)
        else:
            logger.info("No device found in this update.")
            logger.info(
                "-------------------------------------------------------------------------")

    def _updater_timer_expired(self) -> None:
        """Callback method when updater timer is expired"""
        logger.debug('Updater Timer expired. Collect all results.')
        self._collect_result()
        self._data_handler_callback._updater = None  # type: ignore

    def get_remaining_time(self) -> int:
        """Get the remaining time to wait before performing next OTA.

        @return: remaining time to wait before being able to perform next OTA
        """
        return self.updater_timer.get_remaining_wait_time()

    def _get_file_size(self) -> int:
        """Get file size in KB

        @return: returns file size in KB
        """
        total_file_size = 0
        for fp in self._file_paths:
            file = get_canonical_representation_of_path(fp)
            if os.path.exists(file):
                file_size = os.path.getsize(file)
                if file_size > 0:
                    total_file_size = total_file_size + (file_size >> CONVERSION_TO_KB)
                else:
                    # Remove temporary OTA file
                    remove_file(file)
                    raise VisionException("File size wrong value - {0}kb".format(file_size))
            else:
                raise VisionException("Update file not found.")
        return total_file_size

    @staticmethod
    def _create_target(target_ids: List[str]) -> List[OtaTarget]:
        """Create otaTarget for each target to be updated

        @param target_ids: a list of string representing node's device id
        @return: a list containing otaTarget object
        """
        targets_list = []
        for target in target_ids:
            ota_target = OtaTarget(target)
            targets_list.append(ota_target)
        return targets_list

    def _get_target(self, nid: str) -> Optional[OtaTarget]:
        """Get otaTarget from the list

        @param nid: device id of otaTarget
        @return: otaTarget object or None
        """
        logger.debug("Get information of node with deviceID: %s", nid)
        if len(self._targets) != 0:
            for otaTarget_object in self._targets:
                if otaTarget_object.get_node_id() == nid:
                    logger.debug("OTA target found.")
                    return otaTarget_object
        logger.debug("No OTA target found.")
        return None

    def _get_file_index(self, nid: str) -> int:
        """Get current file index from the OtaTarget

        @param nid: device id of otaTarget
        @return: current file index
        """
        if len(self._targets) != 0:
            for otaTarget_object in self._targets:
                if otaTarget_object.get_node_id() == nid:
                    return otaTarget_object.get_file_index()
        return 0

    def _set_file_index(self, nid: str, index: int) -> None:
        """Set current file index of OtaTarget

        @param nid: device id of otaTarget
        @param index: file index to be set
        """
        if len(self._targets) != 0:
            for otaTarget_object in self._targets:
                if otaTarget_object.get_node_id() == nid:
                    otaTarget_object.set_file_index(index)

    def _update_target_status(self, nid: str, status: RequestStatus) -> None:
        """Set OTA update status of otaTarget

        @param nid: device id of otaTarget
        @param status: RequestStatus to be set
        """
        if len(self._targets) != 0:
            for otaTarget_object in self._targets:
                if otaTarget_object.get_node_id() == nid:
                    logger.debug(
                        "Status of %s updated from %s to %s.", otaTarget_object.get_node_id(),
                        otaTarget_object.get_status(), status)
                    otaTarget_object.update_status(status)

    def set_target_error(self, nid: str, error: str) -> None:
        """Set OTA update error message of otaTarget

        @param nid: device id of otaTarget
        @param error: a string representing error message
        """
        if len(self._targets) != 0:
            for target in self._targets:
                if target.get_node_id() == nid:
                    logger.debug(
                        "Set error message to device %s: %s", target.get_node_id(), error)
                    target.set_error(error)
                    target.set_done()
                    self.is_all_targets_done()

    def send_request_to_send_file(self) -> None:
        """Call data handler API to send the file download request with file size  for each node"""
        for ota_target in self._targets:
            logger.debug('Create send file request for device %s.', ota_target.get_node_id())
            if self._file_size is not None:
                self._data_handler_callback.create_download_request(
                    ota_target.get_node_id(), self._file_size)
                ota_target.update_status(RequestStatus.SendDownloadRequest)
                sleep(3)
            else:
                logger.error(
                    "File size error. Please check the file.")

    def update_download_request_status(self, node_id: str, status: bool) -> None:
        """Call data handler API to send OTA update file to node if download request status is
        True.

        If the status is False, an error message will be set to otaTarget.

        @param node_id: string representing node device id
        @param status: True if download request status is True; otherwise, false.
        """
        if status:
            logger.debug('Send Download response of device %s is %s.', node_id, status)
            if self._get_target(node_id):
                self._update_target_status(node_id, RequestStatus.SendFile)
                self._data_handler_callback.send_file(
                    node_id, self._file_paths[self._get_file_index(node_id)])
            else:
                logger.error('Device %s not found.', node_id)
                self.set_target_error(node_id, "Send Download response: Device not found.")

                error_resp = create_error_message(f'OTA FAILURE due to device download request: '
                                                  f'Device {node_id} not found.')
                self._data_handler_callback.send_telemetry_response(node_id, error_resp)
        else:
            logger.error('Send Download response of device %s is %s.', node_id, status)
            if self._get_target(node_id):
                self.set_target_error(node_id, "Send Download response: " + str(status))

                error_resp = create_error_message(
                    f'OTA FAILURE due to device {node_id} download request: Fail.')
                self._data_handler_callback.send_telemetry_response(node_id, error_resp)

    def is_all_targets_done(self) -> bool:
        """Checks if all OTA targets have completed OTA.

        @return: True if all targets done; otherwise, false.
        """
        for t in self._targets:
            if not t.is_done():
                return False
        logger.debug("Stopping timer as all targets have completed %s." % self._update_type)
        self.updater_timer.stop()
        self._updater_timer_expired()
        return True

    def set_done(self, node_id: str) -> None:
        """Sets the status of the target to done.

        @param node_id: Node ID
        """
        logger.debug("set node done: id={}".format(node_id))
        t = self._get_target(node_id)
        if t:
            message = create_success_message(f'NODE {node_id} {self._update_type} SUCCESSFUL.')\
                if t.get_error() == "None" \
                else create_error_message(f'NODE {node_id} {self._update_type} FAILED INSTALL.')
            self._data_handler_callback.send_telemetry_response(node_id, message)
            t.update_status(RequestStatus.RequestComplete)
            t.set_done()


class SotaUpdater(Updater):
    """Manages the requested SOTA update

    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: file to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @param update_interval: integer representing the waiting time to complete the update
    """

    def __init__(self, target_ids: List[str], data_handler: IDataHandler,
                 file_paths: List[str], manifest: Dict[str, str], update_interval: int) -> None:
        super().__init__(target_ids, data_handler, file_paths, manifest, update_interval, 'SOTA')

    def revise_manifest(self, manifest: Dict[str, str]) -> str:
        """Modify SOTA manifest to be sent to node

        @param manifest: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        logger.debug("Revise SOTA manifest start.")
        logger.debug("____________________________________________________________________")
        revised_manifest = (
            '            <manifest>'
            '                <type>ota</type>'
            '                <ota>'
            '                    <header>'
            '                        <type>sota</type>'
            '                        <repo>local</repo>'
            '                    </header>'
            '                    <type>'
            '                        <sota>'
            '                            <cmd logtofile="y">{0}</cmd>'
            '                            <signature>{1}</signature>'
            '                            <path>{2}</path>'
            '                            <release_date>{3}</release_date>'
            '                        </sota>'
            '                    </type>'
            '                </ota>'
            '            </manifest>'
        ).format(
            manifest['cmd'],
            manifest['signature'],
            manifest['path'],
            manifest['release_date']
        )

        logger.debug("%s", revised_manifest)
        logger.debug("____________________________________________________________________")
        logger.debug("Revise SOTA manifest done.")
        return revised_manifest

    def update_download_status(self, node_id: str, status: bool) -> None:
        super().update_download_status(node_id, status)


class FotaUpdater(Updater):
    """Manages the requested FOTA update

    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: files to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @param update_interval: integer representing the waiting time to complete the update
    """

    def __init__(self, target_ids: List[str], data_handler: IDataHandler,
                 file_paths: List[str], manifest: Dict[str, str], update_interval: int) -> None:
        super().__init__(target_ids, data_handler, file_paths, manifest, update_interval, 'FOTA')

    def revise_manifest(self, manifest: Dict[str, str]) -> str:
        """Modify FOTA manifest to be sent to node

        @param manifest: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        logger.debug("Revise FOTA manifest start.")
        logger.debug("____________________________________________________________________")
        revised_manifest = (
            '            <manifest>'
            '                <type>ota</type>'
            '                <ota>'
            '                    <header>'
            '                        <type>fota</type>'
            '                        <repo>local</repo>'
            '                    </header>'
            '                    <type>'
            '                        <fota name="sample">'
            '                            <path>{}</path>'
            '                            <biosversion>{}</biosversion>'
            '                            <vendor>{}</vendor>'
            '                            <manufacturer>{}</manufacturer>'
            '                            <product>{}</product>'
            '                            <releasedate>{}</releasedate>'
            '{}'
            '                        </fota>'
            '                    </type>'
            '                </ota>'
            '            </manifest>'
        ).format(
            manifest['path'],
            manifest['biosversion'],
            manifest['vendor'],
            manifest['manufacturer'],
            manifest['product'],
            manifest['releasedate'],
            '                            <signature>{}</signature>'.format(manifest['signature'])
            if manifest['signature'] else ""
        )

        logger.debug("%s", revised_manifest)
        logger.debug("____________________________________________________________________")
        logger.debug("Revise FOTA manifest done.")
        return revised_manifest

    def update_download_status(self, node_id: str, status: bool) -> None:
        super().update_download_status(node_id, status)


class PotaUpdater(Updater):
    """Manages the requested POTA update

    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: file to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @param update_interval: integer representing the waiting time to complete the update
    """

    def __init__(self, target_ids: List[str], data_handler: IDataHandler,
                 file_paths: List[str], manifest: Dict[str, str], update_interval: int) -> None:
        super().__init__(target_ids, data_handler, file_paths, manifest, update_interval, 'POTA')

    def revise_manifest(self, manifest: Dict[str, str]) -> str:
        """Modify POTA manifest to be sent to node

        @param manifest: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        logger.debug("Revise POTA manifest start.")
        logger.debug("____________________________________________________________________")
        revised_manifest = (
            '            <manifest>'
            '                <type>ota</type>'
            '                <ota>'
            '                    <header>'
            '                        <type>pota</type>'
            '                        <repo>local</repo>'
            '                    </header>'
            '                    <type>'
            '                        <pota>'
            '                            <fota name="sample">'
            '                                <path>{}</path>'
            '                                <biosversion>{}</biosversion>'
            '                                <vendor>{}</vendor>'
            '                                <manufacturer>{}</manufacturer>'
            '                                <product>{}</product>'
            '                                <releasedate>{}</releasedate>'
            '{}'
            '                            </fota>'
            '                            <sota>'
            '                                <cmd logtofile="y">{}</cmd>'
            '                                <path>{}</path>'
            '                                <release_date>{}</release_date>'
            '{}'
            '                            </sota>'
            '                        </pota>'
            '                    </type>'
            '                </ota>'
            '            </manifest>'
        ).format(
            manifest['fota_path'],
            manifest['biosversion'],
            manifest['vendor'],
            manifest['manufacturer'],
            manifest['product'],
            manifest['releasedate'],
            '                                <signature>{}</signature>'.format(
                manifest['fota_signature'])
            if manifest['fota_signature'] else "",
            manifest['cmd'],
            manifest['sota_path'],
            manifest['release_date'],
            '                                <signature>{}</signature>'.format(
                manifest['sota_signature'])
            if manifest['sota_signature'] else ""
        )

        logger.debug("%s", revised_manifest)
        logger.debug("____________________________________________________________________")
        logger.debug("Revise POTA manifest done.")
        return revised_manifest

    def update_download_status(self, node_id: str, status: bool) -> None:
        super().update_download_status(node_id, status)


class ConfigurationLoader(Updater):
    """Manages the configuration load update

    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: file to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @param update_interval: integer representing the waiting time to complete the update
    """

    def __init__(self, target_ids: List[str], data_handler: IDataHandler,
                 file_paths: List[str], manifest: Dict[str, str], update_interval: int, target_type: str) -> None:
        super(ConfigurationLoader, self).__init__(target_ids,
                                                  data_handler,
                                                  file_paths,
                                                  manifest,
                                                  update_interval,
                                                  'LOAD')
        self.target_type = target_type
        logger.debug(
            'Configuration Load update started. Update timer is {} seconds'.format(self._timer))

    def revise_manifest(self, manifest: Dict[str, str]) -> str:
        """Modify manifest to be sent to node

        @param manifest: parsed manifest in dictionary format
        @return: string representing revised manifest
        """
        logger.debug("Revise LOAD manifest start.")
        logger.debug("____________________________________________________________________")
        revised_manifest = '            <path>{0}</path>'.format(manifest['path'])

        logger.debug("%s", revised_manifest)
        logger.debug("____________________________________________________________________")
        logger.debug("Revise LOAD manifest done.")
        return revised_manifest

    def update_download_status(self, node_id: str, status: bool) -> None:
        """Call data handler API to send revised manifest to node if file download status is True.
        If the status is False, an error message will be set to otaTarget.

        @param node_id: string representing node device id
        @param status: boolean representing ota file download status
        """
        if status:
            logger.debug('Download status of device %s is %s.', node_id, status)
            if self._get_target(node_id):
                self._update_target_status(node_id, RequestStatus.SendManifest)
                self._data_handler_callback.send_config_load_manifest(
                    node_id, self._revised_manifest, self.target_type)
            else:
                self._device_not_found(node_id)
        else:
            self._set_error_download_status(node_id)


def get_updater_factory(request_type: str, target_ids: List[str], data_handler: IDataHandler, file_paths: List[str],
                        manifest: Dict[str, str], update_interval: int) -> Updater:
    """Create an OTA factory of a specified OTA type

    @param request_type: Type of request (FOTA, SOTA, POTA)
    @param target_ids: datetime object that represents previous timestamp
    @param data_handler: datetime object that represents current timestamp
    @param file_paths: file to send to Node via Xlink
    @param manifest: manifest with information to be sent to each targeted node
    @para target_type: Type of target
    @param update_interval: integer representing the waiting time to complete the update

    @raise ValueError: Unsupported OTA type
    """

    logger.debug("ota_type: {}".format(request_type))
    if request_type == FOTA:
        return FotaUpdater(target_ids, data_handler, file_paths, manifest, update_interval)
    if request_type == SOTA:
        return SotaUpdater(target_ids, data_handler, file_paths, manifest, update_interval)
    if request_type == POTA:
        return PotaUpdater(target_ids, data_handler, file_paths, manifest, update_interval)
    raise VisionException('Unsupported update type: {}'.format(str(request_type)))
