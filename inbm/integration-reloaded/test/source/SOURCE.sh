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

echo "Starting source test." | systemd-cat

inbc source os list
inbc source application list
# add more cases here
