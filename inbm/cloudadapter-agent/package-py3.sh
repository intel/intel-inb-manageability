#!/bin/bash

# Copyright (C) 2017-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

PACKAGE_TYPE="$1"
PROJECT="$2"
../packaging/build-agent-exe-py3.sh inbm-cloudadapter "$PACKAGE_TYPE" "$PROJECT" agent
