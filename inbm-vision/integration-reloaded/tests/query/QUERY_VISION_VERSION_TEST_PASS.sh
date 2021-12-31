#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

QUERY_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query><option>version</option><targetType>vision</targetType></query></manifest>'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 5 seconds for all agent come up..."
sleep 5

echo Send query update manifest
trigger_vision_ota ma/request/query "${QUERY_XML}"

echo "Wait 3 seconds..."
sleep 3

if journalctl -u inbm-vision | grep "Vision agent version is" ; then
  echo Query vision-agent version test complete.
else
  echo Error in query vision-agent version test.  Showing recent journalctl.
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision
  exit 1
fi
