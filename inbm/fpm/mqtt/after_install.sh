#!/bin/bash

NAME="mqtt"
SYSTEMD_DIR=/lib/systemd/system

after_install() {
    echo "After install called"

    groupadd -f mqtt-broker
    useradd -g mqtt-broker -s /usr/sbin/nologin mqtt-broker

    chmod 0644 ${SYSTEMD_DIR}/systemd/system/mqtt.service
    chmod 0700 /usr/bin/tc-get-tpm-passphrase

    if [ $(cat /proc/1/comm) == "systemd" ]; then
    	echo "Found systemd; attempting to start mqtt service"

    	# Reload daemon to pick up new changes
	systemctl daemon-reload
	echo "Ran systemctl daemon-reload"

	else
    	echo "No systemd found; run mqtt manually"
    fi
}

after_install
