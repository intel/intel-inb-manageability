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

touch /etc/intel-manageability/secret/sample_file.txt

echo "Starting decommission test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>cmd</type><cmd>decommission</cmd></manifest>'

test_echo RUNNING DECOMMISSION TEST
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 200
clean_up_subscribe
