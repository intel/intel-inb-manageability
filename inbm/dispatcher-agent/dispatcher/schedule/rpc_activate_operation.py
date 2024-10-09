"""
    Runs the Rpc command with parameters from the manifest.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from typing import Optional
from ..dispatcher import inbm_common_lib.shell_runner.PseudoShellRunner

logger = logging.getLogger(__name__)


class RpcActivateOperation: 
    def __init__(self, url: str, profile_name: str) -> str:
        return self._execute_rpc_activation_cmd(url, profile_name)

    def _execute_rpc_activation(self, url, name) -> str: 
        command = f""
        (out, err, code) = PseudoShellRunner().run(command)
        if code == 0 and out.strip() == 'success':
            return "Success"
        else:
            return "Failure"
