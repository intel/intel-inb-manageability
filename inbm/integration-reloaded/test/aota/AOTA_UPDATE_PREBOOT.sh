#!/bin/bash
set -euxo pipefail

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting APPLICATION UPDATE preboot test." | systemd-cat

test_echo AOTA UPDATE

inbc aota --uri http://127.0.0.1:80/sample-application-1.0-1.deb -a "application" -c "update"

test_echo Application Update preboot test via INBC.
if listen_event | grep Rebooting... ; then
  echo AOTA UPDATE preboot test good so far.
else
  echo Error in AOTA UPDATE good local test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi

