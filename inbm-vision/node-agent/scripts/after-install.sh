#!/bin/bash
set -e

apparmor_reload() {
	source /etc/os-release
	if [ "$ID" = "ubuntu" ]; then
	    apparmor_parser -r -W -T $1
	else
	    systemctl restart apparmor # KMB's (non-Ubuntu) apparmor_parser will not reload without error
	fi
}

SYSCONFIGDIR=/lib

after_install() {
    echo "After install called"

    groupadd -f node-agent
    # Add node-agent user
    if [ $(grep -c -i 'node-agent' /etc/passwd) -gt 0 ]; then
       echo "Found node agent in group"
    else
      useradd -s /usr/sbin/nologin -g node-agent node-agent
    fi  

    chmod 644 $SYSCONFIGDIR/systemd/system/inbm-node.service

    if [ "$(cat /proc/1/comm)" == "systemd" ]; then
    	echo "Found systemd"
    	echo "Activating node apparmor policies"
		  apparmor_reload /etc/apparmor.d/usr.bin.inbm-node

    	# Reload daemon to pick up new changes
        systemctl daemon-reload
        echo "Ran systemctl daemon-reload"
    else
    	echo "No systemd found; run node manually"
    fi
}

after_install
