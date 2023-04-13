#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR


UCC_MSG='{"some": "arbitrary", "json": "string"}'

test_echo Triggering Good UCC Telemetry Test
listen_ucc_telemetry

trigger_ucc "${UCC_MSG}"
sleep 1
if [ ucc-telemetry-response | grep "$(date +'%Y-%m-%d %H:%M')"]; then
  echo UCC telemetry test good so far
  rm -rf ucc-telemetry-response
else
  echo UCC telemetry test failed
  journalctl -a --no-pager -n 50
  exit 1
fi

