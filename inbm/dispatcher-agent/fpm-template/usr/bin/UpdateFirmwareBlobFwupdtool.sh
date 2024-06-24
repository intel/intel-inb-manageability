#!/bin/bash

# UpdateFirmwareBlobFwupdtool.sh
#
# This script uses fwupdtool to install firmware blobs.
#
# Usage: UpdateFirmwareBlobFwupdtool.sh <GUID> <firmware_file_path>
#
# Parameters:
#   $1 - GUID: The globally unique identifier for the device
#   $2 - firmware_file_path: The full path to the firmware file (.cap)
#
# Example:
#   UpdateFirmwareBlobFwupdtool.sh 1234abcd-5678-efgh-ijkl-9012mnop3456 /path/to/firmware.cap

# Check if both parameters are provided
if [ $# -ne 2 ]; then
    echo "Error: Incorrect number of parameters."
    echo "Usage: $0 <GUID> <firmware_file_path>"
    exit 1
fi

# Assign parameters to named variables for clarity
GUID="$1"
FIRMWARE_PATH="$2"

# Check if the firmware file exists
if [ ! -f "$FIRMWARE_PATH" ]; then
    echo "Error: Firmware file not found at $FIRMWARE_PATH"
    exit 1
fi

# Execute fwupdtool command and check its exit status directly
if ! yes n | fwupdtool install-blob "$FIRMWARE_PATH" "$GUID"; then
    echo "Error: fwupdtool failed to install the firmware" >&2
    exit 1
fi

echo "Firmware update completed successfully"
exit 0
