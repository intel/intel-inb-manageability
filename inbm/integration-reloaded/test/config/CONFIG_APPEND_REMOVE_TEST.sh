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

echo "Starting config append remove test." | systemd-cat

APPEND_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>append</cmd><configtype><append><path>trustedRepositories:htpps://dummyURL.com</path></append></configtype></config></manifest>'
REMOVE_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>remove</cmd><configtype><remove><path>trustedRepositories:htpps://dummyURL.com</path></remove></configtype></config></manifest>'


test_echo RUNNING CONFIG APPEND TEST
test_echo
trigger_ota "${APPEND_XML}"
listen_ota | grep 200
clean_up_subscribe

test_echo RUNNING CONFIG REMOVE TEST
test_echo
trigger_ota "${REMOVE_XML}"
listen_ota | grep 200
clean_up_subscribe