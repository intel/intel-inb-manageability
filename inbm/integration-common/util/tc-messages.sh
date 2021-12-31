#!/bin/bash

suite_started() {
    echo \#\#teamcity\[testSuiteStarted name=\'"$1"\'\]   
    echo "Test suite started: $1" | systemd-cat
}

test_started() {
    echo \#\#teamcity\[testStarted name=\'"$1"\' captureStandardOutput=\'true\'\]
    echo "Test started: $1" | systemd-cat
}

test_pass() {
    echo \#\#teamcity\[testFinished name=\'"$1"\'\]   
    echo "Test pass: $1" | systemd-cat
}

test_fail() {    
    echo \#\#teamcity\[testFailed name=\'"$1"\'\]
    echo \#\#teamcity\[testFinished name=\'"$1"\'\]   
    echo "Test fail: $1" | systemd-cat
    exit 1
}

suite_finished() {
    echo \#\#teamcity\[testSuiteFinished name=\'"$1"\'\]
    echo "Test suite finished: $1" | systemd-cat
}

test_ignored() {
    echo \#\#teamcity\[testIgnored name=\'"$1"\' message=\'"$2"\'\]
}

test_with_command() {  # e.g. test_with_command "Some test" /usr/bin/some_test.sh param1 param2 \"long param 3\"
    testname="$1"
    shift
    test_started "$testname"
    if eval "$@" ; then
        test_pass "$testname"
    else
        test_fail "$testname"
    fi
}
