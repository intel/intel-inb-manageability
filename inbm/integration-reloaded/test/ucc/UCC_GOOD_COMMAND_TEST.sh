#!/bin/bash
set -euxo pipefail # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "TEST FAILED!!!"
}
trap print_all_error ERR


UCC_MSG='{"some": "arbitrary", "json": "string"}'

test_echo Triggering UCC Command Test
listen_ucc_command

trigger_ucc "${UCC_MSG}"
sleep 1
if [ -s ucc-command-response ] && [grep "{"some": "arbitrary", "json": "string"}" ucc-command-response]; then
  echo UCC command test good so far
  rm -rf ucc-command-response
else
  echo UCC command test failed
  journalctl -a --no-pager -n 50
  exit 1
fi

