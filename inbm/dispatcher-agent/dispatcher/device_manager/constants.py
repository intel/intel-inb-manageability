"""
    Constants for DeviceManager classes

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Linux specific constants
LINUX_POWER = "/sbin/shutdown "
LINUX_RESTART = "-r"
LINUX_SHUTDOWN = "-h"
LINUX_SECRETS_FILE = "/var/intel-manageability/secret.img"

# Windows specific constants
WIN_POWER = "shutdown "
WIN_RESTART = "/r"
WIN_SHUTDOWN = "/s"

# Success messages
SUCCESS_RESTART = "Restart Command Success"
SUCCESS_SHUTDOWN = "Shutdown Success"
SUCCESS_DECOMMISSION = "Decommission Success"
