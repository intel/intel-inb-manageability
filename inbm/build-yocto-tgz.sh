#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/build-yocto-tgz-ehl.sh
"$DIR"/build-yocto-tgz-kmb.sh
