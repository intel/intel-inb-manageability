#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting TC16 test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><version>0</version><containerTag>registry.hub.docker.com/library/nginx</containerTag><dockerRegistry>None</dockerRegistry></aota></type></ota></manifest>'

test_echo TC16 Succeed Pull Public Image
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 200
test_echo Checking that import happened.
(trtl -cmd=list | grep nginx)
