#!/bin/bash

workdir=coverage-reports
profile="$workdir/cover.out"
mode=count

mkdir $workdir

for pkg in $(go list ./...);
do
    f="$workdir/$(echo "$pkg" | tr / -).cover"
    go test -v -covermode="$mode" -coverprofile="$f" "$pkg" >> $workdir/test.out
done

set -- "$workdir"/*.cover
if [ ! -f "$1" ]; then
    rm -f "$results" || :
    echo "No Test Cases"; exit 0
fi
echo "mode: $mode" >"$profile"
grep -h -v "^mode:" "$workdir"/*.cover >>"$profile"

rm -f test.xml coverage.xml

#go2xunit -input $workdir/test.out -output test.xml
## Build consolidated coverage report
gocov convert "$profile" | gocov-xml > coverage.xml
## Generate linter report
gometalinter.v1 --install
gometalinter.v1 --checkstyle > report.xml
## Generate unit test report
go test -v ./... | go-junit-report > test.xml

rm -rf $workdir
