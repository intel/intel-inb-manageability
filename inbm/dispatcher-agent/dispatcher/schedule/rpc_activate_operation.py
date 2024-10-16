"""
    Executes the AMT Rpc Activation command.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import Optional
import shlex
from inbm_common_lib.shell_runner import PseudoShellRunner



class RpcActivateOperation: 
    def __init__(self) -> None:
        """RpcActivateOperation class is to execute rpc activate command
        """
        pass

    def execute_rpc_activation_cmd(self, url, name) -> str:
        """Executes the RPC activation command.

        @param url: url address of the RPS
        @param name: profile name used for rpc configuration
        @return: return 'success' if execution succeeds else returns 'Failure'
        """
        url = shlex.quote(url)
        name = shlex.quote(name)
        command = f"rpc activate -u {url}/activate -n --profile {name}"
        (out, err, code) = PseudoShellRunner().run(command)
        if code == 0 and 'CIRA: Configured' in out:
            return "Success"
        else:
            return "Failure"
