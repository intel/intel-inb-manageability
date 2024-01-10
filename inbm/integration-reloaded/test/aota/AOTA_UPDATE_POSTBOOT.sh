#!/bin/bash

set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

echo Checking APPLICATION UPDATE POSTBOOT TEST

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

echo "Waiting for dispatcher to come up postboot..." | systemd-cat
sleep 3
echo "Done waiting for dispatcher." | systemd-cat

dpkg --list | grep sample-application
dpkg --purge sample-application

cleanup_after_test
