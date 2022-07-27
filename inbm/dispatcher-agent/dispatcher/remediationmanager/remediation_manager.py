"""
    Module which fetches and stores external update packages. It fetches a
    package from the specified URL and stores into a configured local cache
    on the device

    Copyright (C) 2017-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging, traceback, re
from ast import literal_eval
from typing import Any, List, Optional, Tuple

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.trtl import Trtl

from ..dispatcher_callbacks import DispatcherCallbacks
from ..packageinstaller.constants import REMEDIATION_CONTAINER_CMD_CHANNEL, \
    REMEDIATION_IMAGE_CMD_CHANNEL

logger = logging.getLogger(__name__)


class RemediationManager:
    """Receives notification from diagnostic to perform remediation management on
    containers/images via TRTL application

    @param dispatcher_callbacks: DispatcherCallbacks instance
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self.ignore_dbs_results = True  # default to WARN until we receive config
        self.dbs_remove_image_on_failed_container = True
        self.container_image_list: List = []

    def run(self) -> None:
        """Subscribes to remediation channels"""
        try:
            logger.debug('Subscribing to: %s', REMEDIATION_CONTAINER_CMD_CHANNEL)
            self._dispatcher_callbacks.broker_core.mqtt_subscribe(
                REMEDIATION_CONTAINER_CMD_CHANNEL, self._on_stop_container)

            logger.debug('Subscribing to: %s', REMEDIATION_IMAGE_CMD_CHANNEL)
            self._dispatcher_callbacks.broker_core.mqtt_subscribe(
                REMEDIATION_IMAGE_CMD_CHANNEL, self._on_remove_image)
        except Exception as exception:  # TODO (Nat): Should catch specific exception
            logger.exception('Subscribe failed: %s', exception)

    def _on_stop_container(self, topic: str, payload: str, qos: int) -> None:
        """Callback for REMEDIATION_CONTAINER_CMD_CHANNEL"""
        #logger.debug("=======================Call stack begin=========================")
        #for line in traceback.format_stack():
        #    logger.debug(line.strip())
        #logger.debug("=======================Call stack end=========================")
        try:
            if payload is not None:
                logger.info('Received message: %s on topic: %s', payload, topic)
                self._remove_container(literal_eval(payload))
        except ValueError as error:
            logger.error('Unable to parse container message . Verify container remove request '
                         'is in the correct format "abc,def,123". {}'.format(error))

    def _on_remove_image(self, topic: str, payload: str, qos: int) -> None:
        """Callback for REMEDIATION_IMAGE_CMD_CHANNEL"""
        #logger.debug("=======================Call stack begin=========================")
        #for line in traceback.format_stack():
        #    logger.debug(line.strip())
        #logger.debug("=======================Call stack end=========================")
        try:
            if payload is not None:
                logger.info('Received message: %s on topic: %s', payload, topic)
                self._remove_images(literal_eval(payload))

        except ValueError as error:
            logger.error('Unable to parse image message . Verify image remove request is in '
                         'the correct format "abc,def,123". {}'.format(error))

    def _remove_images(self, ids: Any) -> None:
        logger.debug("Removing Images...")
        logger.debug(self.container_image_list)
        #for image_id in ids:
        #    self.container_image_list.append(image_id)
        for image_id in ids:
            if image_id not in self.container_image_list:
                self._remove_single_image(image_id)
                self.container_image_list.append(image_id)
        #self.container_image_list[:] = []

    def _remove_single_image(self, image_id: str) -> None:
        logger.debug("")
        if not self.ignore_dbs_results:
            trtl = Trtl(PseudoShellRunner())
            (out, err, code) = trtl.image_remove_by_id(str(image_id), True)
            if err is None:
                err = ""
            if code != 0:
                self._dispatcher_callbacks.broker_core.telemetry('DBS Security issue raised on imageID: '
                                                                 + str(image_id)
                                                                 + '.  Unable to remove image. Error: ' + err)
            else:
                self._dispatcher_callbacks.broker_core.telemetry('DBS Security issue raised on imageID: '
                                                                 + str(image_id)
                                                                 + '.  Image has been removed.')
        else:
            self._dispatcher_callbacks.broker_core.telemetry('DBS Security issue raised on imageID: '
                                                             + str(image_id)
                                                             + '.  Image will not be removed due to system in '
                                                             'DBS WARN mode.')

    def _get_image_id(self, trtl: Trtl, container_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Get the image id associated with the container id via TRTL

        @param trtl: TRTL object
        @param container_id: container ID
        """
        (output, err, code) = trtl.get_image_by_container_id(str(container_id))
        image_id = image_name = None
        if output:
            output_split = output.split(",")
            for value in output_split:
                if "ImageID" in value:
                    image_id = value.replace("ImageID=", "").strip()
                if "ImageName" in value:
                    image_name = value.replace("ImageName=", "").strip()

        logger.debug(
            f"ImageId {image_id} with name {image_name} is associated with containerId {container_id}")
        if code != 0:
            self._dispatcher_callbacks.broker_core.telemetry(
                'Unable to get imageId and imageName for containerID: ' + str(container_id))
            return None, None
        return image_id, image_name
    """
    def _find_current_container(self) -> Optional[str]:
        trtl = Trtl(PseudoShellRunner())
        err, out = trtl.list()
        if err:
            logger.error("Error encountered while getting container ID")
            return None

        logger.debug(f"Container list: {out}")
        
        for line in out.splitlines():
            #if self._name + ":" + str(self._last_version) in line:
            container_id = line.split()[0]
            return container_id
        return None
    """
    def _remove_container(self, ids: Any) -> None:
        for container_id in ids:
            if not self.ignore_dbs_results:
                trtl = Trtl(PseudoShellRunner())
                image_id = None
                #container_id_substring = re.split(r"and|[-,_]",container_id)[1]
                logger.debug(container_id)
                #logger.debug(container_id_substring)
                #if "DBS" in container_id:
                #    continue
                err, out = trtl.list()
                if err:
                    logger.error("Error encountered while getting container ID")

                #if not container_id_substring in str(out) or "DBS" in container_id:
                #    logger.debug(f"{container_id_substring} is not present in list")
                #    continue

                    #return None
                #image_id, image_name = self._get_image_id(trtl, container_id)
                #logger.debug(image_id)
                #logger.debug(image_name)
               
                #logger.debug(self.container_image_list)
                #if image_id is None:
                #    continue

                if self.dbs_remove_image_on_failed_container:
                    image_id, image_name = self._get_image_id(trtl, container_id)
                    if image_id is None:
                        raise ValueError('Cannot read image ID')
                    self.container_image_list.append(image_name)

                (out, err, code) = trtl.stop_by_id(str(container_id))
                if err is None:
                    err = ""
                if code != 0:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'DBS Security issue raised on containerID: ' +
                        str(container_id) + ' unable to stop container. Error: ' + err)
                else:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'DBS Security issue raised on containerID: ' +
                        str(container_id) + '.  Container has been stopped.')

                err = trtl.remove_container(str(container_id), True)
                if err:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'DBS Security issue raised on containerID: ' +
                        str(container_id) + 'unable to remove container. Error: ' + err)
                else:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        'DBS Security issue raised on containerID: ' +
                        str(container_id) + '.  Container has been removed.')

                if self.dbs_remove_image_on_failed_container and image_id is not None:
                    self._remove_single_image(image_id)
            else:
                self._dispatcher_callbacks.broker_core.telemetry(
                    'DBS Security issue raised on containerID: ' + str(container_id) +
                    '.  Container will not be removed due to system in DBS WARN mode.')
