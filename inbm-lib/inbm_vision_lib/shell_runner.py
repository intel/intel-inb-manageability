"""
    Runs shell commands used by the common manageability library
    
    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import shlex
import subprocess
import logging

from typing import List, Tuple

from inbm_common_lib.utility import clean_input
from inbm_vision_lib.path_prefixes import INBM_VISION_BINARY_SEARCH_PATHS

logger = logging.getLogger(__name__)


class PseudoShellRunner:
    """Required to run shell commands"""

    @classmethod
    def run(cls, cmd: str) -> Tuple[str, str, int]:
        """Run/Invoke system commands

        @param cmd: Shell cmd to execute
        @return: Result of subprocess along with output, error & exit status
        """
        cmd = clean_input(cmd)
        shlex_split_cmd = cls.interpret_shell_like_command(cmd)

        logger.debug(
            "run_with_log_path calling subprocess.Popen " +
            str(shlex_split_cmd))

        proc = subprocess.Popen(
            shlex_split_cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        (out, err) = proc.communicate()

        # we filter out bad characters but still accept the rest of the string
        # here based on experience running the underlying command
        return out.decode('utf-8', errors='replace'), err.decode('utf-8', errors='replace'), proc.returncode

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
                for path in INBM_VISION_BINARY_SEARCH_PATHS:
                    exe_file = os.path.join(path, program)
                    if is_exe(exe_file):
                        return exe_file

            return None

        shlex_split_cmd = shlex.split(cmd)
        which_cmd = which(shlex_split_cmd[0])
        if which_cmd:
            shlex_split_cmd[0] = which_cmd
        return shlex_split_cmd
