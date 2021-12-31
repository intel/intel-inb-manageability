#!/bin/bash
set -euxo pipefail

systemctl stop tpm2-abrmd
systemctl disable tpm2-abrmd
udevadm control --reload-rules
udevadm trigger