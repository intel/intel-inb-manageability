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

echo "Starting TC15 test." | systemd-cat

test_echo TC15 Remote Image Install
test_echo Install from remote image
trtl -cmd=import -src=http://127.0.0.1:80/sample-container.tgz -ref=sample-container:10
test_echo Checking that import happened.
(trtl -cmd=list | grep sample-container:10)
