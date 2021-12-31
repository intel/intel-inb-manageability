#!/bin/bash
set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$DIR"/../test_util.sh

test_failed() {
  print_all_error
  echo "Return code: $?"
  echo "TEST FAILED"
}
trap test_failed ERR

echo "Checking health of all services"
check_health_vision_services
echo "Health check passed"
echo "Wait 10 seconds for all agent come up..."
sleep 10

systemctl start nginx

echo "Starting node config get test." | systemd-cat

test_echo RUNNING NODE CONFIG GET TEST via INBC
test_echo
inbc get -tt node -p registrationRetryLimit -t 389C0A

echo "Wait 5 seconds for node processing the manifest..."
sleep 5

if journalctl -u inbm-vision | grep "registrationRetryLimit:" ; then
  echo CONFIG test for NODE passed.
else
  echo Node process config get request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node|dispatcher in system mode)"
  exit 1
fi

echo "Starting node config set test." | systemd-cat
test_echo RUNNING NODE CONFIG SET TEST via inbc
inbc set -tt node -p registrationRetryLimit:11 -t 389C0A

echo "Wait 10 seconds for node processing the manifest..."
sleep 10

if journalctl -u inbm-vision | grep "registrationRetryLimit:11" ; then
  echo CONFIG test for NODE passed.
  clean_up_subscribe
else
  echo Node process config set request fail. Showing recent journalctl.
  journalctl -a --no-pager -n 150 | egrep "( cat|vision|node|dispatcher in system mode)"
  exit 1
fi
