#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

echo Checking SOTA integration test 1: SOTA UPDATE SUCCESS

echo Checking uptime - this should be a fresh boot!
uptime

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

echo "Waiting for dispatcher to finish with sota update success postboot..." | systemd-cat
sleep 30
echo "Done waiting for dispatcher." | systemd-cat

#After reboot
echo After reboot, we are looking for exactly 3 files in /var/lib/dispatcher/upload.
ls /var/lib/dispatcher/upload/
ls /var/lib/dispatcher/upload/ | wc -l | grep 3

echo Also looking for /etc/dispatcher_state to be gone
if [ -f /etc/dispatcher_state ] ; then
  echo ERROR: /etc/dispatcher_state should be removed and is not | systemd-cat
  ls -l /etc/dispatcher_state
  cat /etc/dispatcher_state
  echo "<FAILED> SOTA UPDATE SUCCESS TEST"
  exit 1
fi

echo "<PASS> SOTA UPDATE SUCCESS TEST"
#snapper -c rootConfig list | grep

cleanup_after_test
