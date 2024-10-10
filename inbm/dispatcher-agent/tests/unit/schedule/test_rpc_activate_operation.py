"""
    Execute Rpc Activation command functionality test.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from unittest import TestCase

from unittest.mock import patch
from dispatcher.schedule.rpc_activate_operation import *


class TestRpcActivateOperation(TestCase):

    def setUp(self) -> None:
        self.url = "wss://1.1.1.1"
        self.profile_name = "profilename"
        pass

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('Success', "", 0))
    def test_execute_rpc_activation_cmd_success(self, mock_run) -> None:
        rpc_result = RpcActivateOperation(self).execute_rpc_activation_cmd(self.url, self.name)
        self.assertEqual(rpc_result, 'Success')

    @patch("inbm_common_lib.shell_runner.PseudoShellRunner.run", return_value=('Failure', "", 0))
    def test_execute_rpc_activation_cmd_failure(self, mock_run) -> None:
        rpc_result = RpcActivateOperation(self).execute_rpc_activation_cmd(self.url, self.name)
        self.assertEqual(rpc_result, 'Failure')