"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import fileinput
import logging
import sys
import os

from .constants import GET_UBUNTU_PKG_REPO, APT_SOURCES_LIST_PATH, MENDER_FILE_PATH
from ..common import dispatcher_state
from ..dispatcher_callbacks import DispatcherCallbacks

logger = logging.getLogger(__name__)


class SetupHelper:
    """Abstract class to perform OS-dependent tasks immediately before and after performing
    an OS upgrade
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, list_path):
        """Initializes SetupHelper class
        @param dispatcher_callbacks: Callback to Dispatcher
        @param list_path:
        """
        self._dispatcher_callbacks = dispatcher_callbacks
        self.list_path = list_path

    def pre_processing(self):
        """Perform checks immediately before applying an OS update or upgrade.
        @return: True if OK to proceed; False otherwise
        """
        pass

    def get_snapper_snapshot_number(self) -> str:
        """
        @return: snapshot number from dispatcher state file (FIXME this is not OS generic)
        """
        pass


class DebianBasedSetupHelper(SetupHelper):
    """Debian-based specific implementation of SetupHelper."""

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks):
        """Initializes DebianBasedSetupHelper class

        @param dispatcher_callbacks: callback to dispatcher
        """

        list_path = GET_UBUNTU_PKG_REPO
        super().__init__(dispatcher_callbacks, list_path)

    def pre_processing(self):
        """Perform checks immediately before applying an OS update or upgrade.
        Debian-based: This is a on-disk operation done after taking a snapshot
        It proceeds only if the APT store url was successfully retrieved

        @return: True
        """
        logger.debug("")
        if self._dispatcher_callbacks.sota_repos:
            self.update_sources(self._dispatcher_callbacks.sota_repos)
        return True  # FIXME why do we always return True?

    def update_sources(self, payload: str, filename: str = APT_SOURCES_LIST_PATH) -> None:
        """Update the apt sources.list file with payload if needed
        @param payload: String, http url value retrieved from config manager
        @param filename: file name for sources
        """
        temp_payload = payload.strip()
        if not temp_payload.startswith('http'):
            temp_payload = payload.split(':', 1)[1].strip(' \t\n\r')

        # solves bug 38278
        if not temp_payload.startswith('http'):
            return

        apt_file = fileinput.input(filename, inplace=True, backup='.bak')
        for line in apt_file:
            if line.startswith("#") or line.startswith("\n"):
                sys.stdout.write(line)
                continue
            line_items = line.split()
            need_change = [True if x.find(payload) == -1 else False for x in line_items][0]
            if need_change:
                source_url_list = [line_items.index(x) if x.startswith(
                    "http") else -1 for x in line_items]
                source_url_list.sort()
                source_url_index = source_url_list[-1]
                line_items[source_url_index] = line_items[source_url_index] if line_items[source_url_index].startswith(
                    "https://download.docker.com/") else temp_payload
                print(" ".join(line_items))
            else:
                break
        apt_file.close()

    def get_snapper_snapshot_number(self) -> str:
        """
        @return: snapshot number from dispatcher state file (FIXME this is not OS generic)
        """
        logger.debug("")
        return self.extract_snap_num_from_disk()

    def extract_snap_num_from_disk(self):
        """if dispatcher_state_file exists, it extracts snapshot_num from it

        @return: snapshot_num in integer; None on error
        """
        logger.debug("")
        state = dispatcher_state.consume_dispatcher_state_file()
        if state:
            logger.debug('Read contents of state file: ' + str(state))
            snapshot_num = state['snapshot_num']
            logger.debug(f'Extracting state from disk, extracted snapshot_num: {snapshot_num}')
            return snapshot_num
        return None


class WindowsSetupHelper(SetupHelper):

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks):
        """ Initializes WindowsSetupHelper
        @param dispatcher_callbacks: callback to dispatcher
        """

        super().__init__(dispatcher_callbacks, None)

    def pre_processing(self):
        logger.debug("")
        pass

    def get_snapper_snapshot_number(self) -> str:
        """See parent class for description. This is a stub method on Windows."""

        logger.debug("")
        return ""


class YoctoSetupHelper(SetupHelper):
    """
    Yocto specific implementation of SetupHelper.
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks):
        """ Initializes YoctoSetupHelper
        @param dispatcher_callbacks: callback to dispatcher
        """

        super().__init__(dispatcher_callbacks, None)

    def pre_processing(self):
        """Perform checks immediately before applying an OS update or upgrade.
        Yocto: if Mender Tool is present, it proceeds to perform the OS update
        @return: True if OK to proceed; False otherwise
        """
        logger.debug("Yocto pre processing")
        return self._is_mender_file_exists()

    def _is_mender_file_exists(self):
        """Verifies to see if Mender file is present to perform the OS update
        @return: Boolean value to proceed or not with the OS update
        """
        logger.debug("Checking to see if mender tool exists")
        if os.path.isfile(MENDER_FILE_PATH):
            self._dispatcher_callbacks.broker_core.telemetry("Mender tool found in " + MENDER_FILE_PATH +
                                                             ". Proceeding to perform SOTA.")
            return True
        else:
            self._dispatcher_callbacks.broker_core.telemetry("Mender tool not found in " + MENDER_FILE_PATH +
                                                             ". Aborting SOTA.")
            return False

    def get_snapper_snapshot_number(self) -> str:
        """Gets the snapper snapshot number

        FIXME this is not OS generic)
        """
        logger.debug("Yocto post processing")
        return ""
