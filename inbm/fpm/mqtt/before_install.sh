#!/bin/bash

NAME="mqtt"
SYSTEMD_DIR=/lib/systemd/system

before_install() {
    echo "Before install called"

	if [ $(cat /proc/1/comm) == "systemd" ]; then
		echo "Found systemd; attempting to stop any prior mqtt service"

		# Stop (if any) previous versions of running mqtt service
		if systemctl list-units --type=service | grep '^${NAME}' >/dev/null; then
			systemctl stop ${NAME}
		fi

	# Disable (if any) previous version of mqtt service and remove sym links created by enable command
		if [ -f $SYSTEMD_DIR/${NAME}.service ]; then
			systemctl disable ${NAME}
		fi
	fi
}

before_install
