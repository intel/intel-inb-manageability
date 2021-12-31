#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 20 seconds for all agent come up..."
sleep 20

# Verify node heartbeat is set to 60 seconds, this value may change
if ! journalctl -u inbm-node | grep "heartbeat interval information: 60" ; then
  echo "ERROR: Heartbeat interval is not found."
  print_all_error
  exit 1
fi
echo "Heartbeat interval check passed."

# Verify node agent is added
if ! journalctl -u inbm-vision | grep "One node-agent added " ; then
  echo "ERROR: Node agent is not added into list."
  print_all_error
  exit 1
fi
echo "Node agent add check passed."

# Verify vision-agent is checking heartbeat
if ! journalctl -u inbm-vision | grep "Checking heartbeat." ; then
  echo "ERROR: vision-agent is not checking heartbeat."
  print_all_error
  exit 1
fi
echo "vision-agent heartbeat check passed."

# Verify vision-agent is sending isAlive request when required.
# Stop node agent and wait for 70 minutes
systemctl stop inbm-node
echo "Waiting 70 seconds for isAlive request sent..."
sleep 70
if ! journalctl -u inbm-vision | grep "IsAlive request sent" ; then
  echo "ERROR: vision-agent is not sending isAlive request."
  print_all_error
  exit 1
fi
echo "vision-agent isAlive request check passed."

# TODO: Will implement after BC support re-connection
# Verify Node that already exists is deleted before being added again
#if ! journalctl -u inbm-vision | grep "Delete inbm-node" ; then
#  echo "ERROR: vision-agent is not delete existing node before being added again."
#  print_all_error
#  exit 1
#fi
#echo "vision-agent add existing node check passed."
