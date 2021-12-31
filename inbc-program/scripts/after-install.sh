#!/bin/bash
set -e

MQTT_SERVICE_LOCATION=/etc/systemd/system/mqtt.service
MANAGEABILITY_CACHE_DIR="/var/cache/manageability"
MANAGEABILITY_REPOSITORY_TOOL_DIR="/var/cache/manageability/repository-tool"

after_install() {
	echo "After install called"

}

mkdir -p "$MANAGEABILITY_CACHE_DIR"
mkdir -p "$MANAGEABILITY_REPOSITORY_TOOL_DIR"

after_install
