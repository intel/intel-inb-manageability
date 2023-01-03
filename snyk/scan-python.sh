#!/bin/bash
set -euxo pipefail

# Runs inside docker container and scans an agent
AGENT_PATH="$1"
AGENT_NAME="$2"

. /venv3-snyk/bin/activate >&2
cp -r "$AGENT_PATH" /"$AGENT_NAME"
cd /"$AGENT_NAME"
if [ -f requirements.txt ]; then pip3 install -r requirements.txt >&2; fi
pip3 uninstall -y inbm-lib
grep -v inbm-lib <requirements.txt >tmp
mv tmp requirements.txt
snyk monitor --org=$SNYK_ORG --project-name=iotg-inb-"$AGENT_NAME" /"$AGENT_NAME" -d
snyk test --org=$SNYK_ORG --project-name=iotg-inb-"$AGENT_NAME" /"$AGENT_NAME" -d --json | snyk-to-html \
         -t $(npm config get prefix)/lib/node_modules/snyk-to-html/template/test-cve-report.hbs
