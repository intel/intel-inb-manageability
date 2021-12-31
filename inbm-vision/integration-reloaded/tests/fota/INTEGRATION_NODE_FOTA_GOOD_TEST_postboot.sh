#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

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

sleep 3

echo "Checking health of all services"
check_health_tc_services
echo "Health check passed"

echo After reboot, we are looking for exactly 1 capsule file in /boot/efi/
ls /boot/efi/
ls /boot/efi/ | wc -l | grep 1

echo Also looking for /etc/dispatcher_state to be gone
! [ -f /etc/dispatcher_state ]


echo "Cleaning up after test"
cleanup_after_test
