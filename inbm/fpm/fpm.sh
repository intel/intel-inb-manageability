#!/bin/bash

set -e

NAME=$1
shift

VERSION=$1
shift

ITERATION=$1
shift

EXTENSION=$1
shift

COMMAND="fpm -t ${EXTENSION} $@ --after-install after_install.sh --before-remove before_remove.sh --after-remove after_remove.sh --after-upgrade after_upgrade.sh --before-upgrade before_upgrade.sh --before-install before_install.sh --iteration ${ITERATION} -s dir -C files -p ${NAME}-${VERSION}-${ITERATION}.${EXTENSION} -f -n ${NAME} -v ${VERSION} --no-auto-depends --depends lxc-common -a all -m none ."
echo $COMMAND
$COMMAND
