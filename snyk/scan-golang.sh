#!/bin/bash
set -euxo pipefail

# Runs inside docker container and scans an agent
GOLANG_PATH="$1"
GOLANG_NAME="$2"

cp -r "$GOLANG_PATH" /"$GOLANG_NAME"
cd /"$GOLANG_NAME"
export PATH=$PATH:/go/bin
snyk monitor --org=$SNYK_ORG --project-name=iotg-inb-"$GOLANG_NAME" /"$GOLANG_NAME" -d
snyk test --org=$SNYK_ORG --project-name=iotg-inb-"$GOLANG_NAME" /"$GOLANG_NAME" -d --json| snyk-to-html \
         -t $(npm config get prefix)/lib/node_modules/snyk-to-html/template/test-cve-report.hbs
