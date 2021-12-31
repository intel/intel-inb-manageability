#!/bin/bash

PACKAGE_TYPE="$1"
PROJECT="$2"
../packaging/build-agent-exe-py3.sh inbm-vision "$PACKAGE_TYPE" "$PROJECT" agent
