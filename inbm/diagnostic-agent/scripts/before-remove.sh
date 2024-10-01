#!/bin/bash

AGENT=inbm-diagnostic

echo "Running pre-remove steps for ${AGENT} agent..."

# If it is an upgrade, don't stop and disable the agent.
if [ "$1" = "upgrade" ]; then
    echo "Upgrade in progress, not stopping or disabling ${AGENT} service."
    exit 0
fi

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
