"""
    Executes the AMT Rpc Activation command.

    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import shlex
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)

class RpcActivateOperation:
    def __init__(self) -> None:
        """RpcActivateOperation class is to execute rpc activate command
        """
        pass

    def execute_rpc_activation_cmd(self, url: str, name: str) -> str:
        """Executes the RPC activation command.

        @param url: url address of the RPS
        @param name: profile name used for rpc configuration
        @return: return 'success' if execution succeeds else returns 'Failure'
        """
        url = shlex.quote(url)
        name = shlex.quote(name)
        command = f"rpc activate -u {url}/activate -n -profile {name}"
        try:
            (out, err, code) = PseudoShellRunner().run(command)
            if code == 0:
                return "success"
        except FileNotFoundError as err:
            logger.error(err)

        return "failure"
