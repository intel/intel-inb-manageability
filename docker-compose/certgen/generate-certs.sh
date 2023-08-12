#!/bin/sh
set -e

cert_types="mqtt-broker dispatcher-agent configuration-agent diagnostic-agent"

provisioned=1
for cert_type in $cert_types; do
  if [ ! -f "/${cert_type}-certs/provisioned" ]; then
    provisioned=0
    break
  fi
done

if [ $provisioned -eq 1 ]; then
  echo Done--already provisioned.
  exit 0
fi

mkdir -p /public-certs
mkdir -p /private-certs
echo Generating certs...
/mqtt-deb/usr/bin/inb-provision-certs /public-certs /private-certs

echo Copying certs...
for cert_type in $cert_types; do
  cp /public-certs/"${cert_type}"/"${cert_type}".crt /"${cert_type}"-certs
  cp /private-certs/"${cert_type}"/"${cert_type}".key /"${cert_type}"-certs
  cp /public-certs/mqtt-ca/mqtt-ca.crt /"${cert_type}"-certs
  touch /"${cert_type}"-certs/provisioned # signals to services certs are ready
done

echo Cleaning up...
rm -rf /private-certs
rm -rf /public-certs

echo Done making certs.