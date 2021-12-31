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

CONFIGURATION_PROCESS_MESSAGE='Publishing message: "149" on topic: configuration/update/telemetry/maxCacheSize with retain: False'

SET_CONFIG_MESSAGE='telemetryMessage: Got response back for command: get_element response: {telemetry/maxCacheSize:149}'

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

echo RUNNING INTEGRATION NODE CONFIG - SET TEST via inbc
inbc set -tt node_client -p maxCacheSize:149 -t 389C0A

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

echo Check configuration agent process the config request
if journalctl -u inbm-configuration | grep "$CONFIGURATION_PROCESS_MESSAGE"; then
    echo "node-client - Configuration agent process set config request."
else
    echo "node-client - Configuration agent failed to process set config request."
    echo Test FAILED
    journalctl -u inbm-vision
    journalctl -u inbm-node
    journalctl -u inbm-dispatcher
    journalctl -u inbm-configuration
    exit 1
fi

# Send get config request to check the set value just now
echo Send get config request via inbc
inbc get -tt node_client -p maxCacheSize -t 389C0A

echo "Wait 10 seconds for node processing the manifest..."
sleep 10

echo Check vision-agent get the correct set value
if journalctl -u inbm-vision | grep "$SET_CONFIG_MESSAGE"; then
    echo "vision-agent get the correct set value."
else
    echo "vision-agent failed to get the correct set value."
    echo Test FAILED
    journalctl -u inbm-vision
    journalctl -u inbm-node
    journalctl -u inbm-dispatcher
    journalctl -u inbm-configuration
    exit 1
fi
