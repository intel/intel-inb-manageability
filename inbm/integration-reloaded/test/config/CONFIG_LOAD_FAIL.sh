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

echo "Starting config load fail test." | systemd-cat

BAD_CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><configtype><load><fetch>http://u.intel.com:8000/tc.tar</fetch><signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${CONFIG_FILE}  1234`</signature></load></configtype></config></manifest>'

test_echo FAIL CONFIG LOAD TEST
trigger_ota "${BAD_CONFIG_LOAD_XML}"
listen_ota | grep 400
clean_up_subscribe