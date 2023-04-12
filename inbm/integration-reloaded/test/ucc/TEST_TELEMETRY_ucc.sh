#!/bin/bash
set -x
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"


echo "Running script..."

# Run the Python script and capture stdout, stderr, and the exit code
python3 "$SCRIPT_DIR"/ucc_telemetry_check.py 2>&1
exit_code=$?

echo "Sleeping 1 second..."
sleep 1

echo "Exit code: $exit_code"
exit $exit_code

