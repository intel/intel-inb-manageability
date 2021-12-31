#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

start_time=$(get_time)
print_all_error() {
   echo "Return code: $?"
   echo "TEST FAILED!!!"
}
trap print_all_error ERR

if docker ps -a | grep bench ; then
  echo Saw Docker Bench Security container when none expected.
  false
fi
