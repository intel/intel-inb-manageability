"""
    SOTA snapshot class. Creates a snapshot prior to system update.
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import time

from abc import ABC, abstractmethod
from inbm_lib.trtl import Trtl
from typing import Any, Dict, Optional
from inbm_common_lib.shell_runner import PseudoShellRunner
from .constants import MENDER_FILE_PATH
from .mender_util import read_current_mender_version
from .rebooter import Rebooter
from ..common import dispatcher_state
from .sota_error import SotaError
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)

def mender_commit_command():  # pragma: no cover
    (out, err, code) = PseudoShellRunner.run(MENDER_FILE_PATH + " -help")
    if "-commit" in out or ((err is not None) and "-commit" in err):
        return "mender -commit"
    else:
        return "mender commit"



class Snapshot(ABC):  # pragma: no cover
    """Base class for handling snapshot related task for the system.

    @param trtl: TRTL instance
    @param sota_cmd: SOTA command (update)
    @param dispatcher_callbacks: Callbacks from Dispatcher object
    @param snap_num: snapshot number
    @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
    """

    def __init__(self, trtl: Trtl, sota_cmd: str, dispatcher_callbacks: DispatcherCallbacks, snap_num: Optional[str],
                 proceed_without_rollback: bool) -> None:
        self.trtl = trtl
        self.sota_cmd = sota_cmd
        self._dispatcher_callbacks = dispatcher_callbacks
        self.snap_num = snap_num
        self.proceed_without_rollback = proceed_without_rollback

    @abstractmethod
    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands.

        if Snapshot fails, checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        pass

    @abstractmethod
    def commit(self):
        """Generic method. Call when update is complete and everything is working.

        Always remove dispatcher state file.
        """
        pass

    @abstractmethod
    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        Abstract function. Implementations may reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        pass

    @abstractmethod
    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        Implementations may reboot.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        pass

    @abstractmethod
    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.
        """
        pass


class DebianBasedSnapshot(Snapshot):
    """ Snapshot for Debian OS.

        @param trtl: TRTL instance
        @param sota_cmd: SOTA command (update)
        @param dispatcher_callbacks: Callbacks from Dispatcher object
        @param snap_num: snapshot number
        @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
        """

    def __init__(self, trtl: Trtl, sota_cmd: str, dispatcher_callbacks: DispatcherCallbacks, snap_num: Optional[str],
                 proceed_without_rollback: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         dispatcher_callbacks, snap_num, proceed_without_rollback)

    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands.

        if Snapshot fails,
        it checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        logger.debug("")
        self._dispatcher_callbacks.broker_core.telemetry(
            f"SOTA Attempting snapshot of system before SOTA {self.sota_cmd}")
        try:
            temp_snapshot_num, err = self.trtl.single_snapshot("sota_" + self.sota_cmd)
            if err:
                raise DispatcherException(err)
            snapshot_num: str = temp_snapshot_num.strip(' \t\n\r')
            if snapshot_num:
                restart_reason = None

                state = dispatcher_state.consume_dispatcher_state_file(read=True)
                if state:
                    restart_reason = state.get('restart_reason')
                if restart_reason:
                    state = {'snapshot_num': snapshot_num}
                else:
                    state = {'restart_reason': "sota_" +
                             self.sota_cmd, 'snapshot_num': snapshot_num}

                dispatcher_state.write_dispatcher_state_to_state_file(state)
        except DispatcherException:
            if self.proceed_without_rollback:
                self._dispatcher_callbacks.broker_core.telemetry(
                    "SOTA snapshot of system failed, will proceed "
                    "without snapshot/rollback feature")
            else:
                raise SotaError(
                    'SOTA will not proceed without snapshot/rollback support')
        else:
            self._dispatcher_callbacks.broker_core.telemetry("SOTA snapshot succeeded")
            self.snap_num = snapshot_num

    def _rollback_and_delete_snap(self) -> None:
        """Invokes Trtl to rollback to the snapshot in these conditions:

        a.) After reboot by SOTA, and diagnostic reports bad report for system health
        """
        logger.debug("")
        if self.snap_num:
            self._dispatcher_callbacks.broker_core.telemetry("SOTA attempting rollback")
            rc, err = self.trtl.sota_rollback(self.snap_num)
        else:
            self._dispatcher_callbacks.broker_core.telemetry("SOTA rollback skipped")
            return

        if rc == 0:
            self._dispatcher_callbacks.broker_core.telemetry("Rollback succeeded")
            self.commit()
        else:
            self._dispatcher_callbacks.broker_core.telemetry(
                f"SOTA rollback failed: {err}")

    def commit(self) -> int:
        """Invokes Trtl to delete snapshots in these conditions:

        a.) After reboot by SOTA, and everything works well
        b.) After reboot by SOTA, and diagnostic reports bad report for system health

        Remove dispatcher state file.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        err: Optional[str]
        if self.snap_num is None:
            rc, err = 1, 'snap_num is None'
        else:
            rc, err = self.trtl.delete_snapshot(self.snap_num)
        if err is None:
            err = ''

        if rc == 0:
            self._dispatcher_callbacks.broker_core.telemetry("Snapshot cleanup succeeded")
            return rc
        else:
            self._dispatcher_callbacks.broker_core.telemetry(
                f"SOTA snapshot delete failed: {err}")
            return rc

    def recover(
            self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        On Debian-based OSes, we need to rollback and delete the snapshot, and reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("time_to_wait_before_reboot = " + str(time_to_wait_before_reboot))
        dispatcher_state.clear_dispatcher_state()
        if self.snap_num:
            self._rollback_and_delete_snap()
        else:
            time.sleep(time_to_wait_before_reboot)
        logger.debug("Rebooting to recover from failed SOTA...")
        rebooter.reboot()

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        On Debian-based OSes, we need to rollback, delete snapshot, and reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        if self.snap_num:
            self._rollback_and_delete_snap()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        For Debian-based OSes, we perform no checks.
        """
        pass


class WindowsSnapshot(Snapshot):  # pragma: no cover
    """ Snapshot for Windows.

        @param trtl: TRTL instance
        @param sota_cmd: SOTA command (update)
        @param dispatcher_callbacks: Callbacks from Dispatcher object
        @param snap_num: snapshot number
        @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
        """

    def __init__(self, trtl: Trtl, sota_cmd: str, dispatcher_callbacks: DispatcherCallbacks, snap_num: Optional[str],
                 proceed_without_rollback: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         dispatcher_callbacks, snap_num, proceed_without_rollback)

    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands. if Snapshot fails,

        it checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        pass

    def commit(self) -> None:
        """Invokes Trtl to delete snapshots in these conditions:

        a.) After reboot by SOTA, and everything works well
        b.) After reboot by SOTA, and diagnostic reports bad report for system health

        Delete dispatcher state file.
        """
        dispatcher_state.clear_dispatcher_state()

    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA. Stub. Not implemented for Windows.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        @return: nothing
        """
        logger.debug("")
        pass

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        Stub for Windows.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        pass

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        Stub for Windows.
        """
        pass


class YoctoSnapshot(Snapshot):
    """ Snapshot for Yocto OS.

    @param trtl: TRTL instance
    @param sota_cmd: SOTA command (update)
    @param dispatcher_callbacks: Callbacks from Dispatcher object
    @param snap_num: snapshot number
    @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
   """

    def __init__(self, trtl: Trtl, sota_cmd: str, dispatcher_callbacks: DispatcherCallbacks, snap_num: Optional[str],
                 proceed_without_rollback: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         dispatcher_callbacks, snap_num, proceed_without_rollback)

    def take_snapshot(self) -> None:
        """This method saves the current mender artifact version info in a dispatcher state file

        @raises SotaError: When failed to create a dispatcher state file
        """
        logger.debug("Yocto take_snapshot")
        self._dispatcher_callbacks.broker_core.telemetry(
            "SOTA attempting to create a dispatcher state file before SOTA {}...".
            format(self.sota_cmd))
        try:
            content = read_current_mender_version()
            if dispatcher_state.is_dispatcher_state_file_exists():
                consumed_state = dispatcher_state.consume_dispatcher_state_file(read=True)
                restart_reason = None
                if consumed_state:
                    restart_reason = consumed_state.get('restart_reason', None)
                if restart_reason:
                    state = {'mender-version': content}
            else:
                state = {'restart_reason': "sota", 'mender-version': content}
            dispatcher_state.write_dispatcher_state_to_state_file(state)
        except DispatcherException:
            self._dispatcher_callbacks.broker_core.telemetry(
                "...state file creation unsuccessful.")
            raise SotaError('Failed to create a dispatcher state file')

        self._dispatcher_callbacks.broker_core.telemetry(
            "Dispatcher state file creation successful.")

    def commit(self) -> None:
        """On Yocto, this method runs a Mender commit

        Also, delete dispatcher state file.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        cmd = mender_commit_command()
        logger.debug("Running Mender commit: " + str(cmd))
        PseudoShellRunner.run(cmd)

    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        On Yocto with Mender, no action is required other than deleting the
        state file and rebooting.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        On Ubuntu, we need to rollback, delete snapshot, and reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("time_to_wait_before_reboot = " + str(time_to_wait_before_reboot))
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        For Yocto, we compare the dispatcher state file to current system information
        (from a mender command defined in a constant)
        """

        logger.debug("attempting to get dispatcher state from state file")
        state = dispatcher_state.consume_dispatcher_state_file()
        if state is not None and 'mender-version' in state:
            logger.debug("got mender-version from state: " + str(state['mender-version']))
            version = read_current_mender_version()
            current_mender_version = version
            previous_mender_version = state['mender-version']

            if current_mender_version == previous_mender_version:
                raise SotaError(
                    f"Requested update version is the same as version currently installed. {current_mender_version}")
            else:
                logger.debug("success; mender version changed")

        else:
            raise SotaError(
                f"'mender-version' not in state or state is not available. state = {str(state)}")
