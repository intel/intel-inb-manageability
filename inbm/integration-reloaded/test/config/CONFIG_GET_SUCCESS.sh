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

echo "Starting config get test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>get_element</cmd><configtype><get><path>maxCacheSize</path></get></configtype></config></manifest>'

test_echo RUNNING CONFIG GET TEST
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 200
clean_up_subscribe
