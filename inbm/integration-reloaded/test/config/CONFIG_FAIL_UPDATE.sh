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

echo "Starting config fail update test." | systemd-cat

BAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>maxCacheSize:a</path> </set></configtype></config></manifest>'

test_echo FAIL CONFIG UPDATE TEST
test_echo
trigger_ota "${BAD_XML}"
listen_ota | grep 400
clean_up_subscribe