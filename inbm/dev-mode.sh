#!/bin/bash
set -euxo pipefail

# This script allows a developer to run Intel(R) In-Band Manageability from source on a device
# Assumptions:
# 1. Intel(R) In-Band Manageability is installed and running in binary mode.
# Actions taken:
# 1. Check environment
# 2. Install pip dependencies
# 3. Disable and stop binary agents.

# Confirm we're running as root/sudo
if [ "$EUID" -ne 0 ]
	then echo "Please run as root"
	exit
fi

# Confirm the Intel(R) In-Band Manageability MQTT service is running
if systemctl is-active mqtt; then
	echo "Intel(R) In-Band Manageability MQTT is up and running"
else
	echo "The Intel(R) In-Band Manageability MQTT service must be installed"
	echo "HINT: apt-get install mosquitto mosquitto-clients"
	exit
fi

# Define starting directory
wd=$PWD

# Install System Dependencies
if [ -x "$(command -v apt)" ]; then
    # We are on Ubuntu
	apt-get update
	apt-get install -y software-properties-common
	apt-get update
    apt-get purge -y python3-openssl
    apt-get install -y build-essential libpq-dev libssl-dev openssl libffi-dev zlib1g-dev
	apt-get install -y python3-pip python3-dev python3
else
	echo "We are not on Ubuntu--cannot automatically install Python 3."
fi

if ! which python3 || ! which pip3 ; then
    echo "python3 and pip3 must be installed on system"
    exit 1
fi

echo "Correct Python version found. System ready. Moving on."

#Detect if we're on Elkhart Lake or Keem Bay.
if [ -x "$(command -v apt)" ]; then
	TCPLATFORM=EVAL
else
	if [ "$(uname -m)" = "x86_64" ]; then
		TCPLATFORM=EHL
	else
		TCPLATFORM=KMB
	fi
fi

# Define array of Agents = configuration, diagnostic, dispatcher, telemetry, cloudadapter
declare -a arr=("configuration" "diagnostic" "dispatcher" "telemetry" "cloudadapter")

# Loop through the Agent array and remove old services (if any)
for agent in "${arr[@]}"
	do
	# Remove existing Intel(R) In-Band Manageability services
	if systemctl is-active $agent; then
		echo "Intel(R) In-Band Manageability Services will be stopped and disabled"
		systemctl stop $agent
		systemctl disable $agent
	else
		echo "No existing Intel(R) In-Band Manageability Services"
	fi
done

# install inbm-lib (editable)
pip3 install --proxy=http://proxy-dmz.intel.com:911 -e "$wd"/../inbm-lib

# Install pip requirements for agents
for agent in "${arr[@]}"
do
		cd $wd/$agent-agent
		pip3 install --proxy=http://proxy-dmz.intel.com:911 -r requirements.txt || pip3 install --ignore-installed --proxy=http://proxy-dmz.intel.com:911 -r requirements.txt  # retry on fail with no upgrade for e.g. enum34
done
