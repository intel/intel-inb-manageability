#!/bin/bash
set -euxo pipefail

PACKER_LOG=1 ./packer build sato.json
