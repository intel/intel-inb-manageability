#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

mkdir -p /var/log/sota_test

echo "Triggering SOTA integration INB test 1: SOTA UPDATE SUCCESS"
echo "<START> SOTA UPDATE SUCCESS" | systemd-cat

inbc sota

RESULT=$?
if [ $RESULT -eq 0 ]; then
   echo "<REBOOT> SOTA UPDATE SUCCESS TEST"
else
  echo Test failed to detect non-zero exit code...
  echo "<FAILED> SOTA UPDATE SUCCESS TEST"
  exit 1
fi

# Check status in log file
if grep -Fq "PENDING" ${OTA_LOG_FILE}
then
    echo "<REBOOT> SOTA UPDATE SUCCESS TEST"
    echo "Found PENDING status."
else
    echo "PENDING status not found in log file."
    echo "<FAILED> SOTA UPDATE SUCCESS TEST"
    exit 1
fi