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

CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><targetType>node</targetType><configtype><targets><target>389C0A</target></targets><load><fetch>https://ci_nginx/intel_manageability_node.conf</fetch></load></configtype></config></manifest>'

GET_CONFIG_ELEMENTS=(
  "registrationRetryTimerSecs"
  "registrationRetryLimit"
)

CHECK_GET_MESSAGE=(
  "registrationRetryTimerSecs:15'"
  "registrationRetryLimit:15'"
)

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 5 seconds for all agent come up..."
sleep 5

cp /etc/intel-manageability/public/node-agent/intel_manageability_node.conf "$NGINX_DATA"
sed -i "s|<registrationRetryTimerSecs>20</registrationRetryTimerSecs>|<registrationRetryTimerSecs>15</registrationRetryTimerSecs>|g" "$NGINX_DATA"/intel_manageability_node.conf
sed -i "s|<registrationRetryLimit>9</registrationRetryLimit>|<registrationRetryLimit>15</registrationRetryLimit>|g" "$NGINX_DATA"/intel_manageability_node.conf

systemctl start nginx

echo "Starting config load test on node." | systemd-cat

test_echo RUNNING CONFIG LOAD TEST NODE
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

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

# Send get config request for each element
for i in "${GET_CONFIG_ELEMENTS[@]}"; do
  CONFIG_GET_MANIFEST='<?xml version="1.0" encoding="utf-8"?><manifest><type>config</type><config><cmd>get_element</cmd><targetType>node</targetType><configtype><targets><target>389C0A</target></targets><get><path>'$i'</path></get></configtype></config></manifest>'
  trigger_cloud_ota "${CONFIG_GET_MANIFEST}"
  sleep 2
done

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

# Check value return by get config request
for i in "${CHECK_GET_MESSAGE[@]}"; do
  if journalctl -u inbm-vision | grep $i; then
    echo $i
    # Wait 60 seconds for config timer to expired
    sleep 60
  else
    echo Test FAILED. Message not found: $i
    journalctl -u inbm-vision inbm-node
    exit 1
  fi
done
