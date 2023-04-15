"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import platform
import shlex
import shutil
from pathlib import Path

from inbm_common_lib.constants import AFULNX_64

from dispatcher.dispatcher_exception import DispatcherException
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import move_file
from inbm_lib.constants import DOCKER_CHROOT_PREFIX

from . import constants
from typing import Tuple, Optional, Dict

from .constants import WINDOWS_NUC_PLATFORM
from .fota_error import FotaError
from ..dispatcher_callbacks import DispatcherCallbacks
from ..packagemanager.irepo import IRepo
from abc import ABC
from inbm_common_lib.utility import get_canonical_representation_of_path


logger = logging.getLogger(__name__)


def extract_file_info(pkg_filename: str, repo_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Checks extension of filename and gets filename and certification file name
    @param pkg_filename: name of file (not path)
    @param repo_name: name of repository
    """
    if extract_ext(pkg_filename) in ["package", "bios"]:
        return pkg_filename, None
    else:
        return BiosFactory.unpack(repo_name, pkg_filename)


def extract_ext(file_name: str) -> Optional[str]:
    """Finds file extension

    @param file_name: name of the file that is downloaded
    @return: returns as a package or a cert otherwise None
    """
    logger.debug("inside extract")
    logger.debug(f"file_name={file_name}")
    ext = file_name.rsplit('.', 1)[-1]

    if ext.lower() in {'fv', 'cap', 'bio'}:
        return 'package'
    elif ext.lower() in {'cert', 'pem', 'crt'}:
        return 'cert'
    elif ext.lower() in {'bin'}:
        return 'bios'
    else:
        return None


class BiosFactory(ABC):
    """Abstract Factory for creating the concrete classes based on the BIOS
    on the platform.

    @param dispatcher_callbacks: callback to dispatcher
    @param repo: string representation of dispatcher's repository path
    @param params: platform product parameters
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, params: Dict) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._repo = repo
        self._runner = PseudoShellRunner()
        self._fw_file: Optional[str] = None
        self._cert_filename: Optional[str] = None
        self._config_params = params
        self._guid_required = params.get('guid', None)
        self._fw_tool = params.get('firmware_tool', None)
        self._fw_file_type = params.get('firmware_file_type', None)
        self._fw_tool_args = params.get('firmware_tool_args', '')
        self._fw_dest = params.get('firmware_dest_path', None)
        self._fw_tool_check_args = params.get('firmware_tool_check_args', None)

    def install(self, pkg_filename: str, repo_name: str, tool_options: Optional[str] = None, guid: Optional[str] = None) -> None:
        """Extracts files from the downloaded package and delete the files after the update

        @param pkg_filename: downloaded package filename
        @param repo_name: path to the downloaded package
        @param tool_options: tools options to update firmware
        @param guid: system firmware type
        """
        pass

    @staticmethod
    def get_factory(platform_product: Optional[str], params: Dict, callback: DispatcherCallbacks, repo: IRepo) -> "BiosFactory":
        """Checks if the current platform is supported or not

        @param platform_product: platform product name
        @param params: platform product parameters from the fota conf file 
        @param callback: callback to dispatcher
        @param repo: string representation of dispatcher's repository path
        @raises: FotaError
        """
        logger.debug("")
        fw_dest = params.get('firmware_dest_path', None)
        if platform.system() == "Linux":
            if fw_dest:
                return LinuxFileFirmware(callback, repo, params)
            else:
                return LinuxToolFirmware(callback, repo, params)
        elif platform.system() == 'Windows':
            if (platform_product is not None) and (WINDOWS_NUC_PLATFORM in platform_product):
                logger.debug("Windows NUC product name detected")
                return WindowsBiosNUC(callback, repo, params)
            else:
                raise FotaError("The current Windows system is unsupported.")
        else:
            raise FotaError("Only Linux and Windows are supported.")

    @staticmethod
    def get_files(out: str) -> Tuple[Optional[str], Optional[str]]:
        """Extracts and return the firmware file and the cert file

        @param out: output of untarring the downloaded package
        @return: True, firmware file and cert file on success or False on Failure
        """
        fw_file = cert_file = None
        lines = out.splitlines()
        lines_list = list(dict.fromkeys(lines))
        for line in lines_list:
            if extract_ext(line) == 'package' or extract_ext(line) == 'bios':
                fw_file = line
            elif extract_ext(line) == 'cert':
                cert_file = line

        return fw_file, cert_file

    @staticmethod
    def unpack(repo_name: str, pkg_filename: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract the tar file

        @param repo_name: path to the downloaded package
        @param pkg_filename: downloaded package
        @raises: FotaError
        """
        logger.debug(f"repo_name:{repo_name}, pkg_filename:{pkg_filename}")
        cmd = "tar -xvf " + str(Path(repo_name) / pkg_filename) + \
            " --no-same-owner -C " + repo_name
        (out, err, code) = PseudoShellRunner.run(cmd)
        fw_file, cert_file = BiosFactory.get_files(out)
        if code == 0 and not err:
            return fw_file, cert_file
        else:
            e = f"Firmware Update Aborted: Invalid File sent. error: {err}"
            raise FotaError(e)

    def delete_files(self, pkg_filename: Optional[str], fw_filename: Optional[str], cert_filename: Optional[str]) -> None:
        """Deletes the downloaded and extracted files

        @param pkg_filename: downloaded package filename
        @param fw_filename: firmware filename
        @param cert_filename: cert filename
        """
        logger.debug(" ")
        if pkg_filename:
            self._repo.delete(pkg_filename)
        if fw_filename:
            self._repo.delete(fw_filename)
        if cert_filename:
            self._repo.delete(cert_filename)


class LinuxToolFirmware(BiosFactory):
    """Derived class constructor invoking base class constructor for 
    Linux devices that use Firmware tool to perform the update.

    @param dispatcher_callbacks: callback to dispatcher
    @param repo: string representation of dispatcher's repository path
    @param params: platform product parameters from the fota conf file 
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, params: Dict) -> None:
        super().__init__(dispatcher_callbacks, repo, params)

    def _parse_guid(self, output: str) -> Optional[str]:
        """Method to parse the shell command output to retrieve the value of system firmware type

        @param output: shell command output of ehl firmware tool
        @return: string value if system firmware type is present if not return None
        """
        for line in output.splitlines():
            if "System Firmware type" in line or "system-firmware type" in line:
                return line.split(',')[1].split()[0].strip('{').strip('}')
        return None

    def _extract_guid(self, runner: PseudoShellRunner) -> Optional[str]:
        """Method to get system firmware type

        @param runner: To run shell commands
        @return: None or guid
        """
        cmd = self._fw_tool + " -l"
        (out, err, code) = runner.run(cmd)
        if code != 0:
            raise FotaError("Firmware Update Aborted: failed to list GUIDs: {}".format(str(err)))
        guid = self._parse_guid(out)
        logger.debug("GUID : " + str(guid))
        if not guid:
            raise FotaError("Firmware Update Aborted: No System Firmware type GUID found")
        return guid

    def _apply_firmware(self, repo_name: str, fw_file: Optional[str], guid: Optional[str], tool_options: Optional[str], runner: PseudoShellRunner) -> None:
        """Updates firmware on the platform by calling the firmware update tool

        @param repo_name: path to downloaded package
        @param fw_file: firmware file name
        @param guid: system fw type
        @param tool_options: tool_options used along with fw tool
        @param runner: To run shell commands
        @raises FotaError: on failed firmware attempt
        """
        if self._guid_required:
            if not guid:
                guid = self._extract_guid(runner)
        else:
            guid = ''

        if not tool_options:
            tool_options = ''

        if not fw_file:
            fw_file = ''

        cmd = self._fw_tool + " " + self._fw_tool_args + " " + \
            str(guid) + " " + str(Path(repo_name) / fw_file) + " " + tool_options
        logger.debug(f"Using fw tool: {self._fw_tool}")
        logger.debug("Applying Firmware...")
        if self._fw_tool == AFULNX_64:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Device will be rebooting upon successful firmware install.")
        is_docker_app = os.environ.get("container", False)
        if is_docker_app:
            logger.debug("APP ENV : {}".format(is_docker_app))
            (out, err, code) = runner.run(DOCKER_CHROOT_PREFIX + cmd)
        else:
            (out, err, code) = runner.run(cmd)
        if code == 0:
            self._dispatcher_callbacks.broker_core.telemetry("Apply firmware command successful.")
        else:
            logger.debug(out)
            logger.debug(err)
            if err == '':
                err = "Firmware command failed"
            raise FotaError(f"Error: {err}")

    def install(self, pkg_filename: str, repo_name: str, tool_options: Optional[str] = None, guid: Optional[str] = None) -> None:
        """Extracts files from the downloaded package and delete the files after the update

        @param pkg_filename: downloaded package filename
        @param repo_name: path to the downloaded package
        @param tool_options: tools options to update firmware
        @param guid: system firmware type
        """
        logger.debug(f"pkg_filename: {pkg_filename}, repo_name: {repo_name}")
        if '/' in self._fw_tool:
            if not os.path.isfile(self._fw_tool):
                e = "Firmware Update Aborted:  Firmware tool does not exist at {}".format(
                    self._fw_tool)
                raise FotaError(e)

        if self._fw_tool_check_args:
            runner = PseudoShellRunner()
            cmd = self._fw_tool + " " + self._fw_tool_check_args
            (out, err, code) = runner.run(cmd)
            if code != 0:
                raise FotaError(f"Firmware Update Aborted: Firmware tool: {err}")

        try:
            repo_name = get_canonical_representation_of_path(repo_name)
            self._fw_file, self._cert_filename = extract_file_info(pkg_filename, repo_name)
            self._apply_firmware(repo_name, self._fw_file, guid, tool_options, self._runner)
        except OSError as e:
            raise FotaError(f"Firmware Update Aborted: File unrar failed: error: {e}")
        except (DispatcherException, ValueError, TypeError) as e:
            raise FotaError("{}".format(str(e)))
        finally:
            self.delete_files(pkg_filename, self._fw_file, self._cert_filename)


class LinuxFileFirmware(BiosFactory):
    """Derived class constructor invoking base class constructor for 
    Linux devices that use Firmware file to update firmware.

        @param dispatcher_callbacks: callback to dispatcher
        @param repo: string representation of dispatcher's repository path
        @param params: platform product parameters from the FOTA conf file
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, params: Dict) -> None:
        super().__init__(dispatcher_callbacks, repo, params)

    def install(self, pkg_filename: str, repo_name: str, tool_options: Optional[str] = None, guid: Optional[str] = None) -> None:
        """Extracts files from the downloaded package and applies firmware update and deletes the
        files after the update

        @param pkg_filename: downloaded package filename
        @param repo_name: path to the downloaded package
        @param tool_options: tools options to update firmware
        @param guid: system firmware type
        @raises FotaError:  on failed firmware attempt
        """
        logger.debug(f"pkg_filename={pkg_filename}, repo_name={repo_name}")
        fw_file = cert_filename = None
        try:
            repo_name = get_canonical_representation_of_path(repo_name)
            fw_file, cert_filename = extract_file_info(pkg_filename, repo_name)
            if fw_file is None:
                raise FotaError("firmware file extraction failed")
            move_file(str(Path(repo_name) / pkg_filename[:-3]) + 'fv', self._fw_dest)
            logger.debug("Firmware Update: File successfully moved, new path: {}".format(
                self._fw_dest))
        except (OSError, IOError) as e:
            raise FotaError(f"Firmware Update Aborted: File copy to path failed: error: {e}")
        finally:
            self.delete_files(pkg_filename, fw_file, cert_filename)


class WindowsBiosNUC(BiosFactory):
    """Derived class constructor invoking base class constructor for variable assignment

    @param dispatcher_callbacks: callback to dispatcher
    @param repo: string representation of dispatcher's repository path
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, params: Dict) -> None:
        super().__init__(dispatcher_callbacks, repo, params)

    def install(self, pkg_filename: str, repo_name: str, tool_options: str = None, guid: Optional[str] = None) -> None:
        """Extracts files from the downloaded package and delete the files after the update

        @param pkg_filename: downloaded package filename
        @param repo_name: path to the downloaded package
        @param tool_options: tools options to update firmware (ignored for Windows)
        @param guid: system firmware type (ignored for Windows)
        """

        logger.debug("Inside BIOS factory for Windows NUC")
        logger.debug(f"pkg_filename: {pkg_filename}, repo_name: {repo_name}")
        repo_name = get_canonical_representation_of_path(repo_name)
        msi_full_path = os.path.join(repo_name, pkg_filename)
        logger.debug(f"msi_full_path: {msi_full_path}")
        msi_extract_path = os.path.join(repo_name, pkg_filename + "_extracted")
        logger.debug(f"msi_extract_path: {msi_extract_path}")

        self._check_msi_path(msi_full_path)

        try:
            self._extract_msi(msi_extract_path, msi_full_path)
            self._apply_extracted_bios_update(msi_extract_path)
        finally:
            try:
                shutil.rmtree(msi_extract_path)
            except OSError as e:
                logger.error("Error cleaning up MSI exacted pacakge from FOTA. Error: {}".format(
                    e))
                # We do not want to raise a FOTAException because this is a non-fatal error;
                # we still need to reboot.

    def _check_msi_path(self, msi_full_path: str) -> None:
        if " " in msi_full_path:
            raise FotaError("Space found but not allowed in FOTA package filename or path.")

    def _apply_extracted_bios_update(self, msi_extract_path: str) -> None:
        cwd = os.path.join(msi_extract_path, "ExpressBiosUpdate")
        (out, err, code) = PseudoShellRunner().run(shlex.quote(os.path.join(msi_extract_path,
                                                                            "ExpressBiosUpdate",
                                                                            "DPInst.exe")) +
                                                   " /q /f /se",
                                                   cwd=cwd)
        if code == constants.DPINST_CODE_REBOOT:
            logger.info("FOTA update successful (reboot needed). Installed 1 package.")
        elif code == constants.DPINST_CODE_NO_REBOOT:
            logger.info("FOTA update successful (reboot not needed). Installed 1 package.")
        else:
            raise FotaError(
                "Error code {} while applying BIOS with DPInst (cwd = {})".format(hex(code), cwd))

    def _extract_msi(self, msi_extract_path: str, msi_full_path: str) -> None:
        (out, err, code) = PseudoShellRunner().run("msiexec /a " +
                                                   shlex.quote(msi_full_path) +
                                                   " /qb TARGETDIR=" +
                                                   shlex.quote(msi_extract_path))
        if code != 0:
            raise FotaError("Nonzero error code {} while extracting {} with msiexec".format(
                str(code), msi_full_path))
