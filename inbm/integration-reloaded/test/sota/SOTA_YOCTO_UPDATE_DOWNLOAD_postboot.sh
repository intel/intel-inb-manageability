#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

error_exit() {
  rm -f /etc/force_yocto
  rm -f /usr/bin/mender
  rm -f /mender-was-run
  rm -f /mender-ext4-was-run
}
trap 'error_exit' ERR

source /scripts/test_util.sh

echo Checking SOTA integration SOTA YOCTO UPDATE DOWNLOAD

# wait from 3-120 seconds for dispatcher agent to come up
for i in $(seq 1 40) ; do
    sleep 3
    if ps -G dispatcher-agent | grep dispatcher ; then
        break
    fi
done

# check that dispatcher agent is up
( ps -G dispatcher-agent | grep dispatcher ) || \
( echo "Dispatcher agent did not come up in time." && \
  systemd-analyze critical-chain dispatcher && \
  /bin/false )

sleep 30 # FIXME: adjust downwards when DBS is faster

#After reboot
echo After reboot, we are looking for /mender-was-run
[ -f "/mender-was-run" ]
echo After reboot, we are looking for /mender-ext4-was-run
[ -f "/mender-ext4-was-run" ]

echo Also looking for /etc/dispatcher_state to be gone
! [ -f /etc/dispatcher_state ]

rm -rf /etc/force_yocto /etc/dispatcher_state

cleanup_after_test
