"""
    Runs shell commands used by the common manageability library
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import platform
import os
import shlex
import subprocess
import sys
import logging
import builtins
from datetime import datetime
from subprocess import Popen, PIPE

from typing import Tuple, Optional, Union, BinaryIO, List, Any
from .constants import AFULNX_64
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_BINARY_SEARCH_PATHS


logger = logging.getLogger(__name__)


class PseudoShellRunner:
    """Required to run shell commands"""

    @staticmethod
    # should be Popen[bytes] but not yet supported in this Python version
    def get_process(cmd: Union[str, List[str]]) -> Any:
        """Returns a shell to process a command

        @param cmd: command to execute
        """
        return Popen(cmd, shell=False, stdout=PIPE, preexec_fn=os.setsid)

    @classmethod
    def create_log_file(cls, cmd: str, log_path: Optional[str]) -> Tuple[Optional[BinaryIO], Optional[str]]:
        """Creates the log file in mentioned path

        @param cmd: string format of cmd
        @param log_path: string format of log file's absolute path
        @return: file descriptor and absolute file path
        """
        if log_path is None:
            logger.warning("No log path specified in create_log_file")
        else:
            try:
                logger.debug(
                    f"Trying to create a log directory if it does not exist: {log_path}")
                if not os.path.exists(log_path):
                    os.makedirs(log_path)
                    logger.debug(f"Created Path: {log_path}")
            except OSError as err:
                logger.warning(
                    "Failed to create path: {}, Error: {}".format(
                        log_path, err.strerror))

        if cmd.find("do-release") >= 0:
            filename = "upgrade.log"
        else:
            filename = cmd + "_" + datetime.today().strftime("%d-%m-%Y-%X")

        if log_path is not None:
            abs_log_path = os.path.join(
                log_path, PseudoShellRunner._sanitize(filename))
            logfile = builtins.open(abs_log_path, 'wb')
            return logfile, abs_log_path
        else:
            return None, None

    @classmethod
    def _sanitize(cls, filename: str) -> str:
        """Remove unsafe characters from string filename and return result

        @param filename: name of the file to save logs
        """
        return filename.replace(" ", "_").replace("/", "_")

    @classmethod
    def run_with_log_path(cls,
                          cmd: str,
                          log_path: Optional[str],
                          cwd: Optional[str] = None) -> Tuple[str, Optional[str], int, Optional[str]]:
        """Run/Invoke system commands

        NOTE: on Windows, stderr will appear in stdout instead, alongside stdout,
        due to limitations with Windows services

        @param cmd: Shell cmd to execute
        @param log_path: string format of log file's absolute path
        @param cwd: if not None, run process from this working directory
        @return: Result of subprocess along with output, error (possibly None), exit status, and absolute log path
        """
        shlex_split_cmd = cls.interpret_shell_like_command(cmd)

        logger.debug(
            "run_with_log_path calling subprocess.Popen " +
            str(shlex_split_cmd) +
            " with cwd " + str(cwd))

        if platform.system() == 'Windows':  # Running as a Windows service
            proc = subprocess.Popen(
                shlex_split_cmd,
                cwd=cwd,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        else:
            proc = subprocess.Popen(
                shlex_split_cmd,
                cwd=cwd,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        if log_path or cmd.find("do-release") >= 0:
            (logfile, abs_log_path) = PseudoShellRunner.create_log_file(cmd, log_path)
            if logfile is not None:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        logfile.write(line)
                logfile.close()
        else:
            abs_log_path = None

        logger.debug("")
        (out, err) = proc.communicate(b'yes\n') if AFULNX_64 in cmd else proc.communicate()

        # we filter out bad characters but still accept the rest of the string
        # here based on experience running the underlying command

        decoded_out = out.decode('utf-8', errors='replace')
        if err is None:
            decoded_err = None
        else:
            decoded_err = err.decode('utf-8', errors='replace')

        return decoded_out, decoded_err, proc.returncode, abs_log_path

    @classmethod
    def run(cls, cmd: str, cwd: Optional[str] = None) -> Tuple[str, Optional[str], int]:
        """Run/Invoke system commands

        NOTE: on Windows, stderr will appear in stdout instead, alongside stdout,
        due to limitations with Windows services

        @param cmd: Shell cmd to execute
        @param cwd: if not None, run process from this working directory
        @return: Result of subprocess along with output, error (possibly None) & exit status
        """
        (out, err, code, _) = PseudoShellRunner.run_with_log_path(cmd, log_path=None, cwd=cwd)
        return out, err, code

    @classmethod
    def interpret_shell_like_command(cls, cmd: str) -> List[str]:
        """Take a command intended for a shell and perform minimal
        transformation to allow it to run with shell=False.  Command
        will be split with quoting support and if the command can be found
        in common POSIX locations such as /bin, it will be expanded.

        @param cmd: string with command and arguments
        @return: array suitable for Popen with shell=False
        """

        def which(program):
            import os

            def is_exe(fpath):
                return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

            fpath, fname = os.path.split(program)
            if fpath:
                if is_exe(program):
                    return program
            else:
                if platform.system() == 'Windows':
                    extension = ".exe"
                else:
                    extension = ""

                for path in INTEL_MANAGEABILITY_BINARY_SEARCH_PATHS:
                    exe_file = os.path.join(path, program + extension)
                    if is_exe(exe_file):
                        return exe_file

            return None

        shlex_split_cmd = shlex.split(str(cmd))
        which_cmd = which(shlex_split_cmd[0])
        if which_cmd:
            shlex_split_cmd[0] = which_cmd
        return shlex_split_cmd
