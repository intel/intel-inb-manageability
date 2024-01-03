#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true'  EXIT


cp /etc/apt/sources.list /etc/apt/sources.list.bak
test_failed() {
   cp /etc/apt/sources.list.bak /etc/apt/sources.list
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting source test." | systemd-cat

inbc source os add --sources 'deb test123'
grep 'deb test123' /etc/apt/sources.list
inbc source os list 2>&1 | grep 'deb test123'
inbc source os remove --sources 'deb test123'
! grep 'deb test123' /etc/apt/sources.list

inbc source os add --sources 'deb test123'
inbc source os update --sources 'deb test456' 'deb test789'
! grep 'deb test123' /etc/apt/sources.list
grep 'deb test456' /etc/apt/sources.list
grep 'deb test789' /etc/apt/sources.list

cp /etc/apt/sources.list.bak /etc/apt/sources.list

# TODO
# application add
# application list (check that it's added)
# application update
# application list (check that update is correct)
# application remove
# application list (check that it's removed in /etc/apt/sources.list.d/ and gpg key is gone)