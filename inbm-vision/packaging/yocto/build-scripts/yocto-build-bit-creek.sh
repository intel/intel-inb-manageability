#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${DIR}/../../.. # repo top level
YOCTO_BUILD="/yocto/work_dir/build"

set -e
set -x

wd=$(pwd)

sudo -E -H -u yocto -g yocto /yocto/work_dir/build-recipe.sh

mkdir -p "$wd/output"
#cp -v "$YOCTO_BUILD"/tmp*/deploy/rpm/*/fwupdate-*.rpm "$wd/output"
cp -v "$YOCTO_BUILD"/tmp*/deploy/rpm/*/bit-creek-*.rpm "$wd/output"
