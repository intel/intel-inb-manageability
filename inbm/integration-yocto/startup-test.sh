#!/bin/bash

. ../integration-common/util/tc-messages.sh

suite_started STARTUP
./vagrant-up.sh
test_started STARTUP
if vagrant ssh -c "sudo /test/startup/STARTUP_TEST.sh"; then
	test_pass "update success"
else
	test_fail "update success"
fi
test_ignored "upgrade fail"
suite_finished STARTUP
