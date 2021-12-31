#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Update node version
cp -vf version.txt "$DIR"/node-agent/fpm-template/usr/share/node-agent/version.txt

"$DIR"/dockerfiles/build-Dockerfile.sh check
