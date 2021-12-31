#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting reboot test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>restart</cmd></manifest>'

test_echo RUNNING REBOOT TEST
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 200
clean_up_subscribe
