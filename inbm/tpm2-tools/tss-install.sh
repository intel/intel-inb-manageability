#!/bin/bash

ldconfig
id -u tss &>/dev/null || useradd --system --user-group --no-create-home -s /usr/sbin/nologin tss
