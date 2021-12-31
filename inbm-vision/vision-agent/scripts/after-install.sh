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

    groupadd -f vision-agent
    # Add vision-agent user
    if [ $(grep -c -i 'vision-agent' /etc/passwd) -gt 0 ]; then
       echo "Found vision-agent in group"
    else
      useradd -s /usr/sbin/nologin -g vision-agent vision-agent
    fi  

    chmod 644 $SYSCONFIGDIR/systemd/system/inbm-vision.service

    if [ "$(cat /proc/1/comm)" == "systemd" ]; then
    	echo "Found systemd"
    echo "Activating vision apparmor policies"
		apparmor_reload /etc/apparmor.d/usr.bin.vision
    	# Reload daemon to pick up new changes
		systemctl daemon-reload
		echo "Ran systemctl daemon-reload"
	else
    	echo "No systemd found; run vision-agent manually"
    fi
}

after_install
