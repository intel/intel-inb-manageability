#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/dockerfiles/build-Dockerfile.sh Yocto-tgz-ehl

# maintain backwards compatibility with teamcity scripts for a while
mkdir -p output-yocto-tgz
cp -r output-yocto-tgz-ehl/EHL output-yocto-tgz
rm -rf output-yocto-tgz-ehl
