#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

QUERY_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>query</cmd><query><option>all</option><targetType>node</targetType></query></manifest>'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

systemctl start nginx

# Listen the channel first
(if listen_vision_query | grep "<cmd>query</cmd>"; then
  echo Query manifest is received by vision-agent.
else
  echo printing errors...
  #print_all_error
  echo Error in sending target query manifest.  Showing recent journalctl.
  #journalctl -a --no-pager -n 50 | egrep "( cat|vision|dispatcher in system mode)"
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE-AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi) &

echo Send query update manifest
trigger_vision_ota ma/request/query "${QUERY_XML}"

echo "Wait 5 seconds..."
sleep 5

if journalctl -u inbm-vision | grep "id=389C0A-{'boot_fw_date'" ; then
  echo Query test complete.
else
  echo Error in query test.  Showing recent journalctl.
  echo VISION-AGENT JOURNAL LOG...
  journalctl -u inbm-vision

  echo NODE-AGENT JOURNAL LOG...
  journalctl -u inbm-node
  exit 1
fi

