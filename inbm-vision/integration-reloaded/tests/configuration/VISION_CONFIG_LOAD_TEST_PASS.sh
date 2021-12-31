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

CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><targetType>vision</targetType><configtype><load><fetch>https://ci_nginx/intel_manageability_vision.conf</fetch></load></configtype></config></manifest>'

GET_CONFIG_ELEMENTS=(
  "heartbeatCheckIntervalSecs"
  "heartbeatTransmissionIntervalSecs"
  "fotaCompletionTimerSecs"
  "isAliveTimerSecs"
  "heartbeatRetryLimit"
)

CHECK_GET_MESSAGE=(
  "vision/heartbeatCheckIntervalSecs:15"
  "vision/heartbeatTransmissionIntervalSecs:65"
  "vision/fotaCompletionTimerSecs:125"
  "vision/isAliveTimerSecs:205"
  "vision/heartbeatRetryLimit:3"
)

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

cp /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf "$NGINX_DATA"
sed -i "s|<heartbeatCheckIntervalSecs>11</heartbeatCheckIntervalSecs>|<heartbeatCheckIntervalSecs>15</heartbeatCheckIntervalSecs>|g" "$NGINX_DATA"/intel_manageability_vision.conf
sed -i "s|<heartbeatTransmissionIntervalSecs>60</heartbeatTransmissionIntervalSecs>|<heartbeatTransmissionIntervalSecs>65</heartbeatTransmissionIntervalSecs>|g" "$NGINX_DATA"/intel_manageability_vision.conf
sed -i "s|<fotaCompletionTimerSecs>120</fotaCompletionTimerSecs>|<fotaCompletionTimerSecs>125</fotaCompletionTimerSecs>|g" "$NGINX_DATA"/intel_manageability_vision.conf
sed -i "s|<isAliveTimerSecs>200</isAliveTimerSecs>|<isAliveTimerSecs>205</isAliveTimerSecs>|g" "$NGINX_DATA"/intel_manageability_vision.conf
sed -i "s|<heartbeatRetryLimit>4</heartbeatRetryLimit>|<heartbeatRetryLimit>3</heartbeatRetryLimit>|g" "$NGINX_DATA"/intel_manageability_vision.conf

systemctl start nginx

echo "Starting config load test on vision-agent." | systemd-cat

test_echo RUNNING CONFIG LOAD TEST ON VISION_AGENT
trigger_cloud_ota "${CONFIG_LOAD_XML}"
echo "Testing dispatcher logs..."
sleep 10
if journalctl -u inbm-dispatcher | grep 200; then
    echo "Status 200"
else
    echo Test FAILED
    journalctl -u inbm-dispatcher
    exit 1
fi

echo "Waiting 5 seconds for vision-agent to process the manifest..."
sleep 5

# Send get config request for each element
for i in "${GET_CONFIG_ELEMENTS[@]}"; do
  CONFIG_GET_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd><targetType>vision</targetType><configtype><get><path>'$i'</path></get></configtype></config></manifest>'
  trigger_cloud_ota "${CONFIG_GET_MANIFEST}"
  sleep 2
done

# Check value return by get config request
for i in "${CHECK_GET_MESSAGE[@]}"; do
  if journalctl -u inbm-vision | grep $i; then
    echo $i
  else
    echo Test FAILED. Message not found: $i
    journalctl -u inbm-vision
    exit 1
  fi
done
