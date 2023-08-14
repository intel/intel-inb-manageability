#!/bin/sh
set -e

cert_types="mqtt-broker dispatcher-agent configuration-agent diagnostic-agent inbc-program telemetry-agent"

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

echo Generating certs...
mkdir -p /public-certs
mkdir -p /private-certs
/mqtt-deb/usr/bin/inb-provision-certs /public-certs /private-certs

echo Copying certs...
for cert_type in $cert_types; do
  echo Copying certs for "${cert_type}"...
  cp -v /public-certs/"${cert_type}"/"${cert_type}".crt /"${cert_type}"-certs
  cp -v /private-certs/"${cert_type}"/"${cert_type}".key /"${cert_type}"-certs
  cp -v /public-certs/mqtt-ca/mqtt-ca.crt /"${cert_type}"-certs
  touch /"${cert_type}"-certs/provisioned # signals to services certs are ready
done

echo Cleaning up...
rm -rf /private-certs
rm -rf /public-certs

echo Done making certs.