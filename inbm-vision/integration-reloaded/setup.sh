#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if ! [ -e "$DIR"/input ] ; then
  ln -sf ../output "$DIR"/input
fi

if [ "x$1" == "x18.04" ] ; then
  cp -f Vagrantfile-vm-box-18.04 Vagrantfile-vm-box
elif [ "x$1" == "x20.04" ] ; then
  cp -f Vagrantfile-vm-box-20.04 Vagrantfile-vm-box
else # default
  cp -f Vagrantfile-vm-box-18.04 Vagrantfile-vm-box
fi

vagrant destroy || true
cp -r "$DIR"/../../inbm-lib/inbm_vision_lib/mqttclient input/ # Needed for some reloaded tests
common/setup-nginx-data.sh $PWD/nginx-data $PWD/common

# build inbm (TC)
"$DIR"/../../inbm/build-main.sh
cp "$DIR"/../../inbm/output-main/{Intel*.gz,*.sh} input/
