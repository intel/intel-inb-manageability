#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

if ! [ -e "$DIR"/input ] ; then
  ln -sf ../output "$DIR"/input
fi

if [ "x$1" == "x18.04" ] ; then
  "$DIR"/scripts/select-ubuntu-18.04.sh
elif [ "x$1" == "x20.04" ] ; then
  "$DIR"/scripts/select-ubuntu-20.04.sh
elif [ "x$1" == "x22.04" ] ; then
  "$DIR"/scripts/select-ubuntu-22.04.sh
else # default
  "$DIR"/scripts/select-ubuntu-20.04.sh
fi


vagrant destroy -f || true
cp -r "$DIR"/../../inbm-lib/inbm_lib/mqttclient input/ # Needed for some reloaded tests
../integration-common/setup-nginx-data.sh $PWD/nginx-data $PWD/../integration-common
