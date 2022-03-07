#!/bin/bash
set -uxo # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

INBC_OUTPUT=$(inbc fota -p file_not_exist.tar 2>&1)

sleep 3

if echo "$INBC_OUTPUT" | grep "Failed to execute script INBC"; then
  echo INBC file not found test failed. Script error observed.
  exit 1
fi

if ! echo "$INBC_OUTPUT" | grep "ERROR:Error while copying file: File does not exist or file path is not to a file."; then
  echo INBC file not found test failed. Error not raised.
  exit 1
fi

echo INBC file not found test passed.
