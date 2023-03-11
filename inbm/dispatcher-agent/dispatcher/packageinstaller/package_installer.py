"""
    Module that manages communication with TRTL for OTA package installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from dispatcher.common.result_constants import *
from typing import Any
import logging
from future import standard_library

from dispatcher.config_dbs import ConfigDbs
from .dbs_checker import DbsChecker
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_exception import DispatcherException

standard_library.install_aliases()

logger = logging.getLogger(__name__)


class TrtlContainer:  # pragma: no cover
    """TRTL wrapper. Consists of many wrapper calls to snapshot, do_copy,
    rollback, exec etc.

    @param trtl: TRTL object
    @param name: resource name to be installed
    @param dispatcher_callbacks: DispatcherCallbacks instance
    @param dbs: ConfigDbs.{ON, OFF, WARN}
    """

    def __init__(self, trtl: Any, name: str, dispatcher_callbacks: DispatcherCallbacks, dbs: ConfigDbs) -> None:

        self.__name = name
        self.__trtl = trtl
        self.__last_version = 0
        self._dispatcher_callbacks = dispatcher_callbacks
        self._dbs = dbs
        logger.debug("dbs = " + str(dbs))

    def _start_container(self) -> Result:
        logger.info("image_import: image was created.")
        if self._dbs == ConfigDbs.ON or self._dbs == ConfigDbs.WARN:
            logger.debug("dbs is ON or WARN")
            try:
                message = DbsChecker(self._dispatcher_callbacks, self, self.__trtl, self.__name,
                                     self.__last_version, self._dbs) \
                    .run_docker_security_test()
            except DispatcherException as e:
                logger.error(f'DBS check failed: {str(e)}')
                return INSTALL_FAILURE
            logger.info(message)

            assert self.__name is not None  # noqa: S101
            return self.check_config_params_start_container(self.__name.split(':')[0],
                                                            self.__last_version)
        else:
            # the following line will be optimized out in byte code and only used in unit testing
            assert self.__name is not None  # noqa: S101
            return self.check_config_params_start_container(self.__name.split(':')[0],
                                                            self.__last_version)

    def image_import(self, uri: str) -> Result:
        """Calls TRTL object's import API

        @path uri: URI of source
        @return: Status code showing success or failure of import
        """
        self.__last_version = self._get_import_version()
        if self.__last_version == -1:
            logger.error(
                "image_import: containerTag is incorrect.  Should be in the format 'name:#' Ex. "
                "sample-container:2")
            return INSTALL_FAILURE

        out, is_error, exec_code = self.__trtl.image_import(uri, self.__name)
        if exec_code == 0 and not is_error:
            return self._start_container()
        elif exec_code == 2:
            return IMAGE_IMPORT_FAILURE
        else:
            logger.error("image_import: failed to create image.")
            return INSTALL_FAILURE

    def image_load(self, repo: str) -> Result:
        """Calls TRTL object's load API

        @param repo: repository containing image
        @return: Install success if image was loaded else Install failure
        """
        _, err, exec_code = self.__trtl.image_load(repo, self.__name)
        if exec_code == 0 and not err:
            logger.info("image_load: image was created.")
            tag, err = self.__trtl.get_latest_tag(self.__name)
            if err:
                logger.info("image_load: unable to get image tag.")
            if self._dbs == ConfigDbs.OFF:
                message = "DBS is OFF"
            else:
                try:
                    message = DbsChecker(self._dispatcher_callbacks, self, self.__trtl, self.__name,
                                         self.__last_version, self._dbs) \
                        .run_docker_security_test()
                except DispatcherException:
                    return INSTALL_FAILURE
            logger.info(message)
            return self.check_config_params_start_container(self.__name, int(tag))
        else:
            logger.error("image_load: failed to create image.")
            return INSTALL_FAILURE

    def _get_import_version(self) -> int:
        if self.__name.find(':') == -1:
            return -1

        ver = self.__name.split(':')[1]
        return int(ver) if str(ver).isdigit() else -1

    def _run_start_cmd_without_params(self, name: str, ver: int, container_id: str) -> Result:
        logger.debug("start w/o params")
        self._start_command(name, ver)
        if container_id:
            err = self.__trtl.remove_container(container_id=container_id, force=True)
            if err:
                logger.error("Unable to remove old container, might have a dangling container")
        return INSTALL_SUCCESS

    def check_config_params_start_container(self, name: str, ver: int, container_id=None) -> Result:
        """Runs the correct command to start the container depending on the parameters

        @param name: container name
        @param ver: container version
        @param container_id: ID of the container
        @return: resulting status
        """
        logger.debug("start con")
        try:
            if self.__trtl.params:
                if 'execcmd' in self.__trtl.params:
                    self._execute_command(name, ver, opt=True)
                else:
                    self._start_command(name, ver, opt=True)
                return INSTALL_SUCCESS
            else:
                return self._run_start_cmd_without_params(name, ver, container_id)
        except DispatcherException as err:
            logger.error(str(err))
            return self.rollback()

    def rollback(self) -> Result:
        logger.debug("")
        self.__trtl. \
            rollback(self.__name, self.__last_version,
                     self.__name, self.__last_version - 1)
        logger.debug("rpm_install: rollback complete; returning failure")
        self._start_command(self.__name, self.__last_version - 1)
        return INSTALL_FAILURE

    def _execute_command(self, name: str, ver: int, opt: bool = False) -> None:
        out, is_error, exec_code = self.__trtl.execute(name, ver, opt=opt)
        if exec_code != 0 or is_error:
            raise DispatcherException(
                f"failed to execute command in container. name: {name} ver: {str(ver)}")

    def _start_command(self, name: str, ver: int, opt: bool = False) -> None:
        out, is_error, exec_code = self.__trtl.start(name, ver, opt=opt)
        if exec_code != 0 or is_error:
            raise DispatcherException(
                f"failed to start command in container. name: {name} ver: {str(ver)}")


def _is_valid_extension(file_name: str) -> bool:
    return True if '.rpm' == file_name[-4:] or '.deb' == file_name[-4:] else False
