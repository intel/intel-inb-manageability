#!/bin/bash

set -x

echo ==== journalctl dump filtered to interesting entries ====
journalctl -a -l --no-pager | egrep "( cat|mqtt|vision|node|running in system mode)"

exit 0
