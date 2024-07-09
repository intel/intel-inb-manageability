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

# Alternate usage: UpdateFirmwareBlobFwupdtool.sh -l -- will list system firmware GUIDs

# If "-l", then list system firmware GUIDs in the same format as fwupdate tool
if [ "$1" = "-l" ]; then
    GUIDS=$(fwupdmgr get-devices 2>/dev/null | awk '/System Firmware/,/GUID/' | grep "GUID" | grep -oP '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}')
    if [ -n "$GUIDS" ]; then
        while IFS= read -r GUID; do
            echo "System Firmware type, $GUID"
        done <<< "$GUIDS"
    else
        echo "Error: Unable to retrieve system firmware GUID" >&2
        exit 1
    fi
    exit 0
fi

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
