#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/dockerfiles/build-Dockerfile.sh Windows

# Zip the contents as a package
cd "$DIR"/output-windows/
zip -r inbm-vision-Windows.zip windows-inbm-vision/*
