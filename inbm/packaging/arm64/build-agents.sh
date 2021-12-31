#!/bin/bash
set -xe

rm -rf /output
mkdir -p /output/exe
cd /src
for i in inbm-dispatcher cloudadapter diagnostic telemetry configuration; do
  packaging/run-pyinstaller-py3.sh "$i-agent" "$i"
  cp -r "$i-agent/dist/$i" /output/exe/$i
done
for i in inb ; do
  packaging/run-pyinstaller-py3.sh "$i-program" "$i"
  cp -r "$i-program/dist/$i" /output/exe/$i
done
