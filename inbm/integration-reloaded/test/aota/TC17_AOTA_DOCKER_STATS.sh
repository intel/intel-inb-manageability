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

echo "Starting TC17 test." | systemd-cat

docker run registry.hub.docker.com/library/redis

test_echo Checking that docker stats are shown.
trtl -type=docker -cmd=stats | grep ContainerStats

GOOD_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>stats</cmd><app>docker</app></aota></type></ota></manifest>'

test_echo TC17 Succeed Docker Stats
test_echo
trigger_ota "${GOOD_XML}"

listen_ota | grep 200
