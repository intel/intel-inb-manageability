#!/bin/bash

# Copyright (C) 2017-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

PACKAGE_TYPE="$1"
PROJECT="$2"
../packaging/build-agent-exe-py3.sh inbm-configuration "$PACKAGE_TYPE" "$PROJECT" agent
