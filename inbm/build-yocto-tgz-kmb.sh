#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
docker run --rm --privileged registry.hub.docker.com/multiarch/qemu-user-static --reset -p yes
"$DIR"/dockerfiles/build-Dockerfile.sh Yocto-tgz-kmb

# maintain backwards compatibility with teamcity scripts for a while
mkdir -p output-yocto-tgz
cp -r output-yocto-tgz-kmb/KMB output-yocto-tgz
rm -rf output-yocto-tgz-kmb
