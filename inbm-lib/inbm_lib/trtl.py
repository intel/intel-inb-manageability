"""
    TRTL is a container management tool. Provides a unified front end for
    docker.
    Mainly manages container exec, snapshot, rollback.
    This module constructs the necessary shell commands using the
    appropriate boilerplate to call the TRTL executable

    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""


from typing import Optional, Tuple

import logging
import pipes

from .constants import DOCKER, COMPOSE, TRTL_PATH
from subprocess import Popen, PIPE
import shlex
import time

from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)


class Trtl:
    """
    Class for creating/running TRTL shell commands using a boilerplate
    @param runner: PseudoShellRunner object
    @param app_type: application type TRTL should use to execute the command
    @param config_params: configuration values necessary for the command to execute
    """

    def __init__(self, runner: PseudoShellRunner, app_type: Optional[str] = None, config_params: Optional[str] = None) -> None:
        self.runner = runner
        if app_type is not None:
            self.__app_type = app_type
        else:
            self.__app_type = DOCKER

        if config_params is not None:
            self.params = config_params
        else:
            self.params = ""

    def _boilerplate(self, command: str, **kwargs: str) -> str:
        """Construct command template for TRTL
        @param command: TRTL command
        @return: String representing TRTL command
        """
        txt = ''
        for k, v in kwargs.items():
            txt += ' -' + k + "=" + v

        return TRTL_PATH + " -type=" + self.__app_type + " -cmd=" + command + txt

    def stats(self) -> Optional[str]:
        """Do stats

        @return: code and container usage statistics
        """
        logger.debug("Trtl.stats()")
        (output, err, usage) = self.runner.run(self._boilerplate("stats"))
        for line in output.splitlines():
            if "ContainerStats=" in line:
                logger.debug(line)
                return line.split('=')[1]
        return err

    def image_import(self, url: str, image_name: str) -> Tuple[str, Optional[str], int]:
        """Do import

        @param url: URL location of the image TAR file
        @param image_name: Name and tag to use for image.  'sample-container:2'
        @return: exec_code, is_error, output of trtl command
        """
        logging.debug("Trtl.import(" + image_name + ", " + url + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "import") + " -ref=" + image_name + " -src=" + url)
        logging.debug(
            "Trtl.import results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, err, code

    def image_load(self, path: str, image_name: str) -> Tuple[str, Optional[str], int]:
        """Do load

        @param path: Location of the image tar file
        @param image_name: Name to use for image.
        @return: code, err and version number of image just loaded
        """
        logging.debug("Trtl.load(" + path + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "load") + " -src=" + path + " -ref=" + image_name)
        logging.debug(
            "Trtl.load results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, err, code

    def snapshot(self, image: str) -> Tuple[str, Optional[str], int]:
        """Do snapshot

        @param image: Image whose snapshot is to be taken
        @return: output, optional std error, return code
        """
        logger.debug("Trtl.snapshot(" + str(image) + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "snapshot") + " -in=" + image + " -am=true")
        logging.debug("Trtl.snapshot results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    def get_image_by_container_id(self, container_id: str) -> Tuple[str, Optional[str], int]:
        """Do TRTL GetImageByContainerID

        @param container_id: Container ID
        @return: image id associated with container id
        """
        logger.debug("Trtl.getimagebycontainerid(" + str(container_id) + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "getimagebycontainerid") + " -id=" + str(container_id))
        logging.debug(
            "Trtl.getimagebycontainerid results: output={}, err={}, exitcode={}"
            .format(out, err, code))
        return out, err, code

    def execute(self, image: str, version: int, opt: bool = False) -> Tuple[str, Optional[str], int]:
        """Do TRTL execute

        @param image: Image whose snapshot is to be taken
        @param version: Container tag version
        @param opt: flag which specifies if config params need to be passed or not
        @return: Result, error message, error code
        """
        command = ""
        if opt:
            logger.debug("(1/2) Trtl.execute(" + str(image) + ", " +
                         str(version) + ", ['" + str(self.params) + "'])")
            (out, err, code) = self.runner.run(self._boilerplate("exec") +
                                               " -in=" + image + " -iv=" + str(version) +
                                               " -opt=['" + self.params + "']")
            if err is None:
                err = ""
            logger.debug("(2/2) Stdout: [" + out + "]" + "; stderr: [" + err +
                         "]; return code: " + str(code))
        else:
            logger.debug("(1/2) Trtl.execute(" + str(image) +
                         ", " + str(version) + ", [" + str(command) + "])")
            (out, err, code) = self.runner.run(self._boilerplate("exec") +
                                               " -in=" + image + " -iv=" + str(version) +
                                               " -ec=" + pipes.quote(command))
            if err is None:
                err = ""
            logger.debug("(2/2) Stdout: [" + out + "]" + "; stderr: [" + err +
                         "]; return code: " + str(code))
        return out, err, code

    def image_pull_public(self, image: str, reference: Optional[str], file_name: str = None) \
            -> Tuple[str, Optional[str], int]:
        """Do image pull to public registry

        @param image: image name
        @param reference: remote registry from which to pull image
        @param file_name: file name
        @return: code, err and version number of image pulled
        """

        if image and reference:
            reference = reference + "/" + image
        elif reference is None:
            reference = image

        if self.__app_type == COMPOSE:
            reference = image
            logger.debug("Trtl.pull(" + str(reference) + ")")

            if file_name:
                out, err, code = self.runner.run(
                    self._boilerplate("pull") + " -cf=" + file_name + " -ref=" + reference)
            else:
                out, err, code = self.runner.run(
                    self._boilerplate("pull") + " -ref=" + reference)
        else:
            logger.debug("Trtl.imagepull(" + str(reference) + ")")
            out, err, code = self.runner.run(
                self._boilerplate("imagepull") + " -ref=" + reference)

        logging.debug("pull results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    @staticmethod
    def _send_password(cmd: str, password: str) -> Tuple[str, Optional[str], int]:

        p = Popen(shlex.split(str(cmd)), stdout=PIPE, stdin=PIPE, stderr=PIPE)
        pwd = bytes(password + '\n', 'utf-8')
        (out, err) = p.communicate(input=pwd)
        str_out = out.decode(encoding='utf-8', errors='strict')
        str_err = err.decode(encoding='utf-8', errors='strict')
        logger.debug(f"output: {out!s} error: {err!s}")

        while p.poll() is None:
            time.sleep(0.5)

        logger.debug(f"(2/2) Sending password to TRTL. err={err!s}")
        return str_out, str_err, p.returncode

    def image_pull_private(self, image: str, reference: str, username: str, password: str) -> Tuple[str, Optional[str], int]:
        """Do image pull to private registry

        @param image: image tag
        @param reference: remote registry from which to pull image
        @param username: username to login to private registry
        @param password: password to login to private registry
        @return: code, err and version number of image pulled
        """

        if image and reference:
            reference = reference + "/" + image
        elif reference is None:
            reference = image

        logger.debug(
            "(1/2) Trtl.imagepull(" +
            str(reference) +
            ", " +
            str(username) +
            ")")

        cmd = (
            self._boilerplate("imagepull") +
            " -ref=" +
            str(reference) +
            " -user=" +
            str(username))

        return Trtl._send_password(cmd, password)

    def login(self, private_registry: str, username: str, password: str) -> Tuple[str, Optional[str], int]:
        """Do TRTL login

        @param private_registry: The private docker registry
        @param username: username to login to the docker private registry
        @param password: password to login to docker private registry
        @return: Result, error message, error code
        """

        logger.debug(
            "(1/2) Trtl.login(" +
            str(private_registry) +
            ", " +
            str(username) +
            ")")

        cmd = (self._boilerplate("login") + " -user=" + str(username)
               + " -svr=" + str(private_registry))

        return Trtl._send_password(cmd, password)

    def up(self, image: str, file_name: Optional[str] = None) -> Tuple[str, Optional[str], int]:
        """Do TRTL up (docker-compose)

        @param image: Image to be created/started/attached
        @param file_name: Custom YML file to load on compose
        @return: Result, error message, error code
        """

        logger.debug("Running Trtl.up")
        if file_name is None:
            (out, err, code) = self.runner.run(self._boilerplate(
                "up") + " -in=" + image)
        else:
            (out, err, code) = self.runner.run(self._boilerplate(
                "up") + " -in=" + image + " -cf=" + file_name)
        return out, err, code

    def down(self, image: str, file_name: Optional[str] = None) -> Tuple[str, Optional[str], int]:
        """Do TRTL down (docker-compose)

        @param image: Image to be stopped
        @param file_name: File name
        @return: Result, error message, error code
        """
        logger.debug("Trtl.down(" + image + ")")
        if file_name is None:
            out, err, code = self.runner.run(self._boilerplate("down") + " -in=" + image)
        else:
            out, err, code = self.runner.run(self._boilerplate(
                "down") + " -in=" + image + " -cf=" + file_name)
        logging.debug(
            "Trtl.down results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, err, code

    def start(self, image: str, version: int, opt: bool = False) -> Tuple[str, Optional[str], int]:
        """Do TRTL start

        @param image: Image to be started
        @param version: Image version
        @param opt: flag which specifies if config params need to be passed or not
        @return: Result, error message, error code
        """

        if opt:
            logger.debug("(1/2) Trtl.start(" + str(image) + ", " + str(
                version) + ", ['" + str(self.params) + "'])")
            (out, err, code) = self.runner.run(self._boilerplate("start") +
                                               " -in=" + image + " -iv=" + str(version) +
                                               " -opt=['" + self.params + "']")
            if err is None:
                err = ""
            logger.debug("(2/2) Stdout: [" + out + "]" + "; stderr: [" + err +
                         "]; return code: " + str(code))
        else:
            logger.debug("(1/2) Trtl.start(" + str(image) + ", " + str(
                version))
            (out, err, code) = self.runner.run(self._boilerplate(
                "start") + " -in=" + image + " -iv=" + str(version))
            if err is None:
                err = ""
            logger.debug("(2/2) Stdout: [" + out + "]" + "; stderr: [" + err +
                         "]; return code: " + str(code))
        return out, err, code

    def rollback(self, in_image: str, in_version: int, out_image: str, out_version: int) -> Tuple[str, Optional[str], int]:
        """Do TRTL rollback

         @param in_image: Rollback from image
         @param in_version: Rollback from image version
         @param out_image: Rollback to image
         @param out_version: Rollback to image version

         @return: Result, error message, error code
         """
        logger.debug("Trtl.rollback(" + in_image + ", " + str(in_version) +
                     ", " + out_image + ", " + str(out_version) + ")")
        out, err, code = self.runner.run(self._boilerplate("rollback") +
                                         " -in=" + in_image + " -iv=" + str(in_version) +
                                         " -sn=" + out_image + " -sv=" +
                                         str(out_version))
        logging.debug("Trtl.rollback results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    def commit(self, image: str, version: int) -> Tuple[str, Optional[str], int]:
        """Do TRTL commit

        @param image: Image to be committed
        @param version: Image version
        @return: Result, error message, error code
        """
        logger.debug("Trtl.commit(" + image + ", " + str(version) + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "commit") + " -in=" + image + " -iv=" + str(version))
        logging.debug("Trtl.commit results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    def stop(self, image: str, version: int = -1) -> Tuple[str, Optional[str], int]:
        """Do TRTL stop

        @param image: Image to be stopped
        @param version: Image version; -1 means no version, 0 means latest
        @return: Result, error message, error code
        """
        logger.debug("Trtl.stop(" + image + ", " + str(version) + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "stop") + " -in=" + image + " -iv=" + str(version))
        logging.debug(
            "Trtl.stop results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, err, code

    def stop_by_id(self, container_id: str) -> Tuple[str, Optional[str], int]:
        """Do TRTL stopByID
        @param container_id: ContainerID to be stopped
        @return: Result, error message, error code
        """
        logger.debug("Trtl.stopByID(" + container_id + ")")
        out, err, code = self.runner.run(
            self._boilerplate("stopByID") + " -id=" + container_id)
        logging.debug("Trtl.stop_by_id results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    def stop_all(self, image: str) -> Tuple[str, Optional[str], int]:
        """
        Do TRTL stopAll
        @param image: Container image to be stopped
        @return: Result, error message, error code
        """
        logger.debug("Trtl.StopAll(" + image + ")")
        out, err, code = self.runner.run(self._boilerplate("StopAll") + " -in=" + image)
        logging.debug("Trtl.stopAll results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return out, err, code

    def image_remove_by_id(self, image_id: str, force: bool = False) -> Tuple[str, Optional[str], int]:
        """Do TRTL imageRemoveByID
        @param image_id: ImageID to be removed
        @param force: Force image to be removed even if it has an active container
        @return: Result, error message, error code
        """
        logger.debug("Trtl.imageRemoveByID(" + image_id + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "imageRemoveByID") + " -id=" + image_id + " -f=" + str(force))
        logging.debug(
            "Trtl.imageremovebyid results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, err, code

    def get_latest_tag(self, image: str) -> Tuple[str, int]:
        """Get Latest Tag used for an image.

        @param image: Image of which the latest tag should be found
        @return: Latest tag number being used
        """
        logger.debug("Trtl.getlatesttag(" + image + ")")
        (out, err, code) = self.runner.run(self._boilerplate("getlatesttag") +
                                           " -in=" + image)
        logging.debug(
            "Trtl.getlatesttag results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return out, code

    def remove_old_images(self, image: str) -> Optional[str]:
        """Remove old images of the image name specified.
        This would look into config file for how many old images to keep
        for the image name specified and would remove any images older than the number specified.

        @param image: Image name of which the older versions should be deleted
        @return: error if any
        """
        if self.__app_type == COMPOSE:
            logger.info(
                "Removing old images not currently supported when using Compose.")
            return None

        logger.debug("Trtl.removeoldimage(" + image + ")")
        (out, err, code) = self.runner.run(
            self._boilerplate("imagedeleteold") + " -in=" + image)
        logging.debug(
            "Trtl.removeoldimage results: output={}, err={}, exitcode={}".format(
                out, err, code))
        if code != 0 and err != '':
            return err
        else:
            return None

    def list(self, container_id: Optional[str] = None) -> Tuple[Optional[str], str]:
        """Lists all the running containers

        @param container_id: Image name
        @return: error if any and the list
        """
        if container_id is None:
            container_id = ''

        logger.debug(f"Trtl.list: container_id->{container_id}")
        out, err, code = self.runner.run(
            self._boilerplate("list") + " -in=" + container_id)
        logging.debug(
            "Trtl.list results: output={}, err={}, exitcode={}".format(
                out, err, code))
        if code != 0 and err != '':
            return err, ''
        else:
            return None, out

    def image_remove_all(self, image: str, force: bool = False) -> Tuple[str, Optional[str], int]:
        """
        Do TRTL Remove All images (e.g. compose images)

        @param image: Image to be stopped
        @param force: Force image to be removed even if it has an active container
        @return: Result, error message, error code
        """
        logger.debug("Trtl.imageRemoveAll(" + image + ")")
        out, err, code = self.runner.run(self._boilerplate(
            "ImageRemoveAll") + " -in=" + image + " -f=" + str(force))
        logging.debug(
            "Trtl.imageRemoveAll results: output={}, err={}, exitcode={}" .format(
                out, err, code))
        return out, err, code

    def remove_container(self, container_id: str, force: bool) -> Optional[str]:
        """Removes container with the container_id specified

        @param container_id: Image name of which the older versions should be deleted
        @param force: Whether if should do force removal or not (e.g of a running container)
        @return: error if any
        """
        logger.debug("Trtl.containerRemove(" + container_id + ")")
        if force:
            (out, err, code) = self.runner.run(self._boilerplate(
                "containerRemoveByID" + " -f") + " -id=" + container_id)
        else:
            (out, err, code) = self.runner.run(self._boilerplate(
                "containerRemoveByID") + " -id=" + container_id)

        logging.debug(
            "Trtl.containerRemove results: output={}, err={}, exitcode={}".format(
                out, err, code))
        if code != 0 and err != '':
            return err
        else:
            return None

    def single_snapshot(self, desc: str) -> Tuple[str, Optional[str]]:
        """Creates a snapper snapshot of type single on BTRFS fs with given description.
        @param desc: Description to use for snapshot

        @return: stdout and error if any
        """
        logger.debug("Trtl.singlesnapshot()")
        (out, err, code) = self.runner.run(
            self._boilerplate("singleSnapshot", description=desc))
        logging.debug(
            "Trtl.singlesnapshot results: output={}, err={}, exitcode={}".format(
                out, err, code))
        if code != 0:
            return out, err
        else:
            return out, ''

    def delete_snapshot(self, snapshot: str) -> Tuple[int, Optional[str]]:
        """Trtl wrapper to delete a particular snapshot.

        @return: code and error if any
        """
        logger.debug("Trtl.delete_snapshot()")
        (out, err, code) = self.runner.run(
            self._boilerplate("deleteSnapshot", iv=str(snapshot)))
        logging.debug(
            "Trtl.delete_snapshot results: output={}, err={}, exitcode={}".format(
                out, err, code))
        return code, err

    def sota_rollback(self, snapshot: str) -> Tuple[int, Optional[str]]:
        """Trtl wrapper to perform rollback to a given snapshot.

        @return: error if any
        """
        logger.debug("Trtl.rollback()")
        (out, err, code) = self.runner.run(
            self._boilerplate("UndoChange", sv=str(snapshot)))
        logging.debug("Trtl.rollback results: output={}, err={}, exitcode={}"
                      .format(out, err, code))
        return code, err

    def run_docker_bench_security_test(self) -> Optional[str]:
        """Runs DBS script via TRTL
        @return: output from DBS script
        """
        cmd = self._boilerplate("dockerbenchsecurity")
        out, err, code = self.runner.run(cmd)

        if code == 0:
            logger.debug("Docker security bench executed")
            return out
        else:
            if err is None:
                err = ""
            logger.debug("Could not run docker security bench : " + err)

        return None
