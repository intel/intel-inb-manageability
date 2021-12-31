#!/bin/bash

AGENT=inbm-telemetry

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
