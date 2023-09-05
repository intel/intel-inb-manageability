#!/bin/bash
set -euxo pipefail

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT

test_failed() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting APPLICATION UPDATE preboot test." | systemd-cat

GOOD_XML='<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="sample-rpm"><cmd>update</cmd><app>application</app><fetch>http://127.0.0.1:80/sample-application-1.0-1.deb</fetch><deviceReboot>yes</deviceReboot><version>0</version></aota></type></ota></manifest>'

test_echo AOTA UPDATE

inbc aota --uri http://127.0.0.1:80/U1170000F60X043.bin -a "application" -c "update"

test_echo Application Update preboot test via INBC.
#trigger_ota "${GOOD_XML}"
if listen_event | grep Rebooting... ; then
  echo AOTA UPDATE preboot test good so far.
else
  echo Error in AOTA UPDATE good local test preboot.  Showing recent journalctl.
  journalctl -a --no-pager -n 50
  exit 1
fi

