#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

mkdir -p /var/log/sota_test

echo "Triggering SOTA integration INB test: SOTA UPDATE SUCCESS NO SNAPSHOT"
mv /usr/bin/snapper /usr/bin/snapper.bak
echo "<START> SOTA UPDATE SUCCESS NO SNAPSHOT" | systemd-cat

rm -rf /var/lib/dispatcher/upload/*

inbc sota

RESULT=$?
if [ $RESULT -eq 0 ]; then
   echo "<REBOOT> SOTA UPDATE SUCCESS NO SNAPSHOT"
else
  echo Test failed to detect non-zero exit code...
  echo "<FAILED> SOTA UPDATE SUCCESS NO SNAPSHOT"
  journalctl -a --no-pager -n 150 | egrep "( cat|dispatcher in system mode)"
  exit 1
fi
