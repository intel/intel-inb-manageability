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

echo "Starting AOTA fail test." | systemd-cat

BAD_AOTA_XML_WITH_NO_REPO_TAG='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>aota</type></header><type><aota name="sample-rpm"><cmd>pull</cmd><app>docker</app><version>0</version><containerTag>hello-world</containerTag><dockerRegistry>None</dockerRegistry></aota></type></ota></manifest>'

test_echo FAIL AOTA WITH MISSING MANDATORY TAG IN MANIFEST TEST
test_echo
trigger_ota "${BAD_AOTA_XML_WITH_NO_REPO_TAG}"
listen_ota | grep 300

