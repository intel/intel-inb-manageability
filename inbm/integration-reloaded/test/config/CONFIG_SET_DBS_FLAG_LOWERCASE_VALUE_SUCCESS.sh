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

echo "Starting config set dbs flag in lowercase value test." | systemd-cat

cp /etc/intel_manageability.conf intel_manageability_old.conf

GOOD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>set_element</cmd><configtype><set><path>dbs:off</path></set></configtype></config></manifest>'

test_echo RUNNING CONFIG SET TEST
test_echo
trigger_ota "${GOOD_XML}"
listen_ota | grep 200
grep "off" /etc/intel_manageability.conf

cp intel_manageability_old.conf /etc/intel_manageability.conf
systemctl restart inbm-configuration
clean_up_subscribe
