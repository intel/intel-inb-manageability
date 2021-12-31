#!/bin/bash

NAME="mqtt"

# Stop service
if systemctl list-units --type=service | grep '^${NAME}' >/dev/null; then
	systemctl stop ${NAME}
fi