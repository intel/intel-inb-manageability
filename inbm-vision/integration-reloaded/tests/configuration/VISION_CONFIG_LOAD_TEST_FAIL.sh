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

CONFIG_LOAD_XML='<?xml version="1.0" encoding="UTF-8"?><manifest><type>config</type><config><cmd>load</cmd><targetType>vision_node</targetType><configtype><load><fetch>https://ci_nginx/intel_manageability_vision.conf</fetch></load></configtype></config></manifest>'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

cp /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf "$NGINX_DATA"
echo "<!-- CONFIG LOAD TEST VISION -->" >>"$NGINX_DATA"/intel_manageability_vision.conf

! grep "CONFIG LOAD TEST VISION" /etc/intel-manageability/public/vision-agent/intel_manageability_vision.conf

check_request_on_channel() {
  if listen_config_request | grep intel_manageability_vision ; then
    echo Config command received by vision-agent
  else
    echo Config command failed to reach the vision-agent.
    echo Printing DISPATCHER logs...
    journalctl -n 50 -u inbm-dispatcher
    exit 1
  fi
}

systemctl start nginx

echo "Starting config load test on vision-agent." | systemd-cat

test_echo RUNNING CONFIG LOAD TEST VISION-AGENT
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
#check_request_on_channel

echo "Wait 10 seconds for vision-agent processing the manifest..."
sleep 10


if journalctl -u inbm-vision | grep 300; then
    echo "Status 300"
else
    echo Test FAILED
    journalctl -u inbm-vision
    exit 1
fi
