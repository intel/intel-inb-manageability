#!/bin/bash

echo "After install called"
chmod +x /usr/bin/trtl

if aa-status > /dev/null; then
    echo "AppArmor detected.  Activating trtl's AppArmor policies."
    apparmor_parser -r -W -T /etc/apparmor.d/usr.bin.trtl
else
    echo "AppArmor not detected.  Skipping policy activation."
fi
