#!/bin/bash

set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

echo Checking DECOMMISSION POSTBOOT TEST

echo Checking uptime - this should be a fresh boot!
uptime

echo Also After shutdown, looking for file from /etc/intel-manageability/secret/ to be gone
! [ -f /etc/intel-manageability/secret/sample_file.txt ]

cleanup_after_test
