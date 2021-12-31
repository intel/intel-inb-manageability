#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

echo Reconnecting vision-agent and node-agent
vagrant ssh -c "sudo chmod a+rw /tmp/xlink_mock"
vagrant ssh -c "sudo systemctl restart inbm-vision"
sleep 10