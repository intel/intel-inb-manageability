#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_BUILDKIT=1 "$DIR"/dockerfiles/build-Dockerfile.sh Windows