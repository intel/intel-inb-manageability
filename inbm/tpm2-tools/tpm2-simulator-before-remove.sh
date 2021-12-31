#!/bin/bash
set -euxo pipefail

systemctl disable tpm2-simulator
systemctl stop tpm2-simulator