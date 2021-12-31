#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/dockerfiles/build-Dockerfile.sh Windows

# Zip the contents as a package
# Zip inbm-broker
mkdir -p windows-inbm-broker/intel-manageability
rsync -a output-windows/windows/intel-manageability/broker windows-inbm-broker/intel-manageability/
rsync -a output-windows/windows/intel-manageability/inbm/etc/public/mqtt-broker windows-inbm-broker/intel-manageability/broker/etc/public/
rm -rf output-windows/windows/intel-manageability/broker
rm -rf output-windows/windows/intel-manageability/inbm/etc/public/mqtt-broker
mv output-windows/windows/intel-manageability/install-broker.ps1 windows-inbm-broker/intel-manageability/
mv output-windows/windows/intel-manageability/inbm/bin/inb-provision-certs.exe windows-inbm-broker/intel-manageability/broker/usr/bin
mv output-windows/windows/intel-manageability/mosquitto.conf windows-inbm-broker/intel-manageability/
mv output-windows/windows/mosquitto-* windows-inbm-broker/intel-manageability/
mv output-windows/windows/third-party-programs.txt windows-inbm-broker/intel-manageability/
mv output-windows/windows/vc_redist* windows-inbm-broker/intel-manageability/
mv output-windows/windows/Win64OpenSSL_Light-* windows-inbm-broker/intel-manageability/
zip -r inbm-broker-Windows.zip windows-inbm-broker/*
mv inbm-broker-Windows.zip output-windows/
rm -rf windows-inbm-broker/

# Zip inbm
mkdir -p windows-inbm/
cp -r output-windows/windows/* windows-inbm/
zip -r inbm-Windows.zip windows-inbm/*
mv inbm-Windows.zip output-windows/
rm -rf windows-inbm/