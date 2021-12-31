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


export https_proxy=http://proxy-chain.intel.com:912/ 
export http_proxy=http://proxy-chain.intel.com:912/ 
export no_proxy=127.0.0.1,localhost,*.intel.com

sudo -E -H -u yocto -g yocto /yocto/work_dir_"$BUILD_TYPE"/build-img.sh
