#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${DIR}/../../.. # repo top level

set -e
set -x

usage() {
  echo "Usage: $0 [build type]";
  echo "";
  echo "[build type] = EHL or KMB or GENERIC"
  echo "";
}

if [ $# -ne 1 ]; then
  usage
  exit 1
fi

BUILD_TYPE="$1"
YOCTO_BUILD="/yocto/work_dir_$BUILD_TYPE/build"


wd=$(pwd)

sudo -E -H -u yocto -g yocto /yocto/work_dir_"$BUILD_TYPE"/build-recipe.sh

mkdir -p "$wd/output"
#cp -v "$YOCTO_BUILD"/tmp*/deploy/rpm/*/fwupdate-*.rpm "$wd/output"
cp -v "$YOCTO_BUILD"/tmp*/deploy/rpm/*/inb-*.rpm "$wd/output"
