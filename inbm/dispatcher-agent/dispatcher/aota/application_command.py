"""
    AOTA Application Command Concrete Classes

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
import shutil

from typing import Optional, Any, Mapping

from inbm_lib.detect_os import is_inside_container
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import canonicalize_uri, remove_file, get_canonical_representation_of_path, move_file
from inbm_lib.constants import DOCKER_CHROOT_PREFIX, CHROOT_PREFIX, OTA_SUCCESS

from dispatcher.config_dbs import ConfigDbs
from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.common.result_constants import CODE_OK
from dispatcher.constants import OTA_PACKAGE_CERT_PATH, UMASK_OTA, REPO_CACHE
from dispatcher.packagemanager.package_manager import get, verify_signature

from .checker import check_application_command_supported, check_url, check_resource
from .aota_command import AotaCommand
from .constants import CENTOS_DRIVER_PATH, SupportedDriver, CMD_SUCCESS, CMD_TERMINATED_BY_SIGTERM
from .cleaner import cleanup_repo, remove_directory
from .aota_error import AotaError
from ..update_logger import UpdateLogger
from ..dispatcher_broker import DispatcherBroker

logger = logging.getLogger(__name__)


class Application(AotaCommand):
    """Performs Application updates triggered via AOTA

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: Config.dbs value
    """

    def __init__(self,
                 dispatcher_broker: DispatcherBroker,
                 parsed_manifest: Mapping[str, Optional[Any]],
                 dbs: ConfigDbs,
                 update_logger: UpdateLogger) -> None:
        # security assumption: parsed_manifest is already validated
        super().__init__(parsed_manifest, dbs)
        self._update_logger = update_logger
        self._dispatcher_broker = dispatcher_broker

    def verify_command(self, cmd: str) -> None:
        check_application_command_supported(cmd)

    def run_signature_check(self, path_to_file: str) -> None:
        """
        Runs the signature check on the given file to authenticate the OTA update package.

        This method checks if the device is provisioned with an OTA package check certificate.
        If the device is provisioned and a signature is provided, it will verify the signature
        of the file using the specified hash algorithm. If the signature verification fails or
        if a signature is not provided while the device is provisioned, it raises an AotaError.

        If the device is not provisioned for signature verification, a warning is logged, and
        the signature check is skipped.

        @param path_to_file: The file path to the OTA update package that needs to be verified.

        @return: None. It may raise an AotaError if a required signature is not provided or
        if verification fails.
        """
        if os.path.exists(OTA_PACKAGE_CERT_PATH):
            if self._signature is not None:
                verify_signature(dispatcher_broker=self._dispatcher_broker,
                                 hash_algorithm=self._hash_algorithm,
                                 path_to_file=path_to_file,
                                 signature=self._signature)
            else:
                logger.error("Signature required to proceed with OTA update.")
                raise AotaError(
                    "Device is provisioned with OTA package check certificate. Cannot proceed without signature.")
        else:
            no_signature_warning = 'WARNING: Device not provisioned for signature check.  Skipping signature check.'
            logger.warning(no_signature_warning)
            self._dispatcher_broker.telemetry(no_signature_warning)

    def cleanup(self) -> None:
        if self.repo_to_clean_up is not None and self.resource is not None:
            cleanup_repo(self.repo_to_clean_up, self.resource)
            remove_directory(self.repo_to_clean_up)

    def identify_package(self, package_name: str) -> Optional[str]:
        """
        @param package_name: driver package's name

        @return: name of driver to be removed
        """
        driver_name = None
        for driver in SupportedDriver:
            if driver.value in package_name:
                driver_name = driver.value
        return driver_name

    def _download_package(self) -> DirectoryRepo:
        if self._uri is None:
            raise AotaError("missing URI.")

        check_resource(self.resource, self._uri, self._dispatcher_broker)

        logger.debug("AOTA to download a package")
        self._dispatcher_broker.telemetry(
            f'OTA Trigger Install command invoked for package: {self._uri}')
        application_repo = AotaCommand.create_repository_cache_repo()
        get_result = get(url=canonicalize_uri(self._uri),
                         repo=application_repo,
                         umask=UMASK_OTA,
                         username=self._username,
                         password=self._password)
        self._dispatcher_broker.telemetry(
            f'Package: {self._uri} Fetch Result: {get_result}')

        if get_result.status != CODE_OK:
            raise AotaError(f"Unable to download application package. Status = {get_result.status}, message = {get_result.message}.")
        
        return application_repo

    def _reboot(self, cmd: str) -> None:
        if self._device_reboot in ["Yes", "Y", "y", "yes", "YES"]:  # pragma: no cover
            # Save the log before reboot
            self._update_logger.status = OTA_SUCCESS
            self._update_logger.error = ""
            self._update_logger.save_log()

            logger.debug(f" Application {self.resource} installed. Rebooting...")
            self._dispatcher_broker.telemetry('Rebooting...')
            (output, err, code) = PseudoShellRunner().run(cmd)
            if code != CMD_SUCCESS and code != CMD_TERMINATED_BY_SIGTERM:
                raise AotaError(f'Reboot Failed {err}')

    def update(self) -> None:
        """Performs Application Update
        Sets the result variable to failure or success based on the result

        @raise: AotaError when application download or installation fails
        """
        check_url(self._uri)


class CentOsApplication(Application):
    def __init__(self,
                 dispatcher_broker: DispatcherBroker,
                 parsed_manifest: Mapping[str, Optional[Any]],
                 dbs: ConfigDbs,
                 update_logger: UpdateLogger) -> None:
        # security assumption: parsed_manifest is already validated
        super().__init__(dispatcher_broker, parsed_manifest, dbs, update_logger)

    def cleanup(self) -> None:
        """Clean up AOTA temporary file and the driver file after use"""
        logger.debug("")
        for d in os.listdir(get_canonical_representation_of_path(REPO_CACHE)):
            if d.startswith("aota") and os.path.isdir(os.path.join(REPO_CACHE, d)):
                shutil.rmtree(get_canonical_representation_of_path(os.path.join(REPO_CACHE, d)))
        # Clean up driver files
        for file in os.listdir(CENTOS_DRIVER_PATH):
            remove_file(os.path.join(CENTOS_DRIVER_PATH, file))

    def _is_rpm_file_type(self, file_path: str) -> bool:
        """Check the driver file is rpm type or not

        @return: return False if file is not rpm type
        """
        return True if file_path.endswith('.rpm') else False

    def update(self) -> None:
        """ Update CentOS driver"""
        super().update()
        application_repo = self._download_package()

        # Check if it's CentOS and inside container. In CentOS inb container, chroot is used to switch to CentOS
        # rootfs and install the driver.
        driver_path = application_repo.get_repo_path() + "/" + self.resource if self.resource else ""

        logger.debug(f"driver path = {driver_path}")
        try:
            self.run_signature_check(driver_path)

            if not self._is_rpm_file_type(driver_path):
                raise AotaError('Invalid file type')

            # Remove all files in inb_driver
            for file in os.listdir(CENTOS_DRIVER_PATH):
                remove_file(os.path.join(CENTOS_DRIVER_PATH, file))

            driver_centos_path = os.path.join(CENTOS_DRIVER_PATH, driver_path.split('/')[-1])
            logger.debug(f"driver_centos_path = {driver_centos_path}")
            # Move driver to CentOS filesystem
            move_file(driver_path, driver_centos_path)

            old_driver_name = self.identify_package(driver_path.split('/')[-1])
            if not old_driver_name:
                raise AotaError(
                    f'AOTA Command Failed: Unsupported driver {driver_path.split("/")[-1]}')
            uninstall_driver_cmd = CHROOT_PREFIX + \
                f'/usr/bin/rpm -e --nodeps {old_driver_name}'
            out, err, code = PseudoShellRunner().run(uninstall_driver_cmd)

            # If old packages wasn't install on system, it will return error too.
            if code != 0 and "is not installed" not in str(err):
                raise AotaError(err)

            chroot_driver_path = driver_centos_path.replace("/host", "")
            install_driver_cmd = CHROOT_PREFIX + \
                f'/usr/bin/rpm -ivh {chroot_driver_path}'
            logger.debug(f" Updating Driver {driver_path.split('/')[-1]} ...")
            out, err, code = PseudoShellRunner().run(install_driver_cmd)
            logger.debug(out)
            if code != 0:
                raise AotaError(err)
            self._reboot(CHROOT_PREFIX + '/usr/sbin/shutdown -r 0')

        except (AotaError, FileNotFoundError, OSError, IOError) as error:
            # Remove temp files if the error happened.
            msg = str(error)
            try:
                self.cleanup()
            except FileNotFoundError as e:
                msg = f'{msg} and during cleanup: {e}'
            raise AotaError(f'AOTA Command Failed: {msg}')


class UbuntuApplication(Application):
    """Performs Application updates triggered via AOTA on Ubuntu.
    Capable of detecting whether running in container (update Ubuntu host)
    and escaping container if needed.

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: Config.dbs value
    """

    def __init__(self,  dispatcher_broker: DispatcherBroker,
                 parsed_manifest: Mapping[str, Optional[Any]], dbs: ConfigDbs,
                 update_logger: UpdateLogger) -> None:
        # security assumption: parsed_manifest is already validated
        super().__init__(dispatcher_broker, parsed_manifest, dbs, update_logger=update_logger)

    def update(self):  # pragma: no cover
        super().update()
        application_repo = self._download_package()
        path_to_pkg = os.path.join(application_repo.get_repo_path(),
                                   self.resource) if self.resource else ""
        if ' ' in path_to_pkg or path_to_pkg.isspace():
            logger.debug(f"INSTALL : {path_to_pkg}")
            raise AotaError(f"File path cannot contain spaces - {path_to_pkg}")

        self.run_signature_check(path_to_file=path_to_pkg)

        base_command = f"/usr/bin/dpkg -i {path_to_pkg}"

        is_docker_app = os.environ.get("container", False)
        if is_docker_app:
            command = DOCKER_CHROOT_PREFIX + base_command
        else:
            command = base_command
        logger.debug(f" Updating Application {self.resource} ...")
        out, err, code = PseudoShellRunner().run(command)
        logger.debug(f" Application update logs {out} and error {err}")
        if code != 0:
            raise AotaError(err)

        reboot_base_command = "/sbin/reboot"
        if is_docker_app:
            reboot_command = DOCKER_CHROOT_PREFIX + reboot_base_command
        else:
            reboot_command = reboot_base_command

        self._reboot(reboot_command)
