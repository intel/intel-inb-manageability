"""
    Execute Rpc Activation command functionality test.

    Copyright (C) 2025 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from unittest import TestCase
from unittest.mock import patch
from dispatcher.schedule.rpc_activate_operation import *


class TestRpcActivateOperation(TestCase):

    def setUp(self) -> None:
        self.url = "wss://1.1.1.1"
        self.profile_name = "udmProfilename"

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('success', "", 0))
    def test_execute_rpc_activation_cmd_success(self, mock_run) -> None:
        rpc_result = RpcActivateOperation().execute_rpc_activation_cmd(self.url, self.profile_name)
        self.assertEqual(rpc_result, 'success')

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('failure', "", -1))
    def test_execute_rpc_activation_cmd_failure(self, mock_run) -> None:
        rpc_result = RpcActivateOperation().execute_rpc_activation_cmd(self.url, self.profile_name)
        self.assertEqual(rpc_result, 'failure')