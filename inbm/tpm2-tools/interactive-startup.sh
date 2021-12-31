#!/bin/bash
set -e

dpkg -i /debs-18.04/*.deb

if ! systemctl is-enabled tpm2-simulator ; then
    echo ERROR: tpm2-simulator is not enabled
    exit -1
fi

rm -f /usr/lib/libtss2-tcti-default.so
sed -i -e 's/ExecStart=\/usr\/sbin\/tpm2-abrmd/ExecStart=\/usr\/sbin\/tpm2-abrmd --tcti=mssim/g' /lib/systemd/system/tpm2-abrmd.service
systemctl daemon-reload
systemctl restart tpm2-simulator 
systemctl restart tpm2-abrmd

clear

echo tpm2 interactive simulator environment ready
echo try: tpm2_takeownership -o "ownerpass" -e "" -l ""
/bin/bash
