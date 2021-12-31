#!/bin/bash

AGENT=inbm-vision
PROVISIONED_FILE=/etc/intel-manageability/secret/.provisioned_vision

echo "Running pre-remove steps for ${AGENT} agent..."

# Stop service
if systemctl is-active ${AGENT} ; then
	echo "Stopping ${AGENT} agent."
	systemctl stop ${AGENT}
else
    echo "The ${AGENT} agent is already stopped."
fi

# Disable service
if systemctl is-enabled ${AGENT} ; then
	echo "Disabling ${AGENT} agent."
	systemctl disable ${AGENT}
else
	echo "The ${AGENT} agent is already disabled."
fi

# Remove provisioned file
if [ -f "$PROVISIONED_FILE" ] ; then
  rm "$PROVISIONED_FILE"
  echo "Remove provisioned file."
fi
