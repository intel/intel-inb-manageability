#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

test_failed() {
  print_all_error
  echo "Return code: $?"
  echo "TEST FAILED"
}
trap test_failed ERR

CONFIG_GET_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd><targetType>vision</targetType><configtype><get><path>heartbeatCheckIntervalSecs</path></get></configtype></config></manifest>'

CONFIG_SET_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>set_element</cmd><targetType>vision</targetType><configtype><set><path>heartbeatCheckIntervalSecs:11;heartbeatRetryLimit:4</path></set></configtype></config></manifest>'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10


echo Send set config manifest to vision-agent
trigger_cloud_ota "${CONFIG_SET_MANIFEST}"

echo "Wait 5 seconds for vision-agent configuration to set element..."
sleep 5

if journalctl -u inbm-vision | grep "vision/heartbeatRetryLimit:4:SUCCESS" ; then
  echo  Vision-agent set element test passed
else
  echo Error in vision-agent set element test.  Showing recent journalctl.
  journalctl -u inbm-vision
  # journalctl -a --no-pager -n 50
  exit 1
fi

echo Send get config manifest to vision-agent
trigger_cloud_ota "${CONFIG_GET_MANIFEST}"

echo "Wait 5 seconds for vision-agent configuration to get element..."
sleep 5

if journalctl -u inbm-vision | grep "vision/heartbeatCheckIntervalSecs:11:SUCCESS" ; then
  echo  Vision-agent get element test passed
  clean_up_subscribe
else
  echo Error in vision-agent get element test.  Showing recent journalctl.
  journalctl -u inbm-vision
  # journalctl -a --no-pager -n 50
  exit 1
fi