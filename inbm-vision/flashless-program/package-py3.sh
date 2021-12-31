#!/bin/bash
set -e

PACKAGE_TYPE="$1"
PROJECT="$2"
../packaging/build-agent-exe-py3.sh flashless "$PACKAGE_TYPE" "$PROJECT" program
