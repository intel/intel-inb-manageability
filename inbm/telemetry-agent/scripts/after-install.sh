#!/bin/bash
set -e

apparmor_reload() {
	source /etc/os-release
	if [ "$ID" = "ubuntu" ]; then
	    apparmor_parser -r -W -T $1
	else
	    systemctl restart apparmor # KBY's (non-Ubuntu) apparmor_parser will not reload without error
	fi
}

SYSTEMD_DIR=/lib/systemd/system

after_install() {
    echo "After install called"

    chmod 644 $SYSTEMD_DIR/inbm-telemetry.service

    if [ "$(cat /proc/1/comm)" == "systemd" ]; then
    	echo "Found systemd"
		echo "Activating inbm-telemetry's apparmor policies"
		apparmor_reload /etc/apparmor.d/usr.bin.inbm-telemetry
    	# Reload daemon to pick up new changes
		systemctl daemon-reload
		echo "Ran systemctl daemon-reload"
	else
    	echo "No systemd found; run inbm-telemetry manually"
    fi
}

after_install
