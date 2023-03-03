"""
    Constants and other config variables used throughout the packagemanager module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Location of ca certs file on Linux
LINUX_CA_FILE = '/etc/ssl/certs/ca-certificates.crt'

# Buffer size for streaming the downlaod file to check its size
STREAM_BUFFER = 4000  # 4KB to avoid leaving L1 cache
