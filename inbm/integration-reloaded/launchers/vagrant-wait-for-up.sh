#!/bin/bash
set -e

echo Waiting for machine to come back up...
counter=0 # Max 2 minute wait
while ( ! vagrant ssh -c "/bin/true" >&/dev/null && [ $counter -lt 120 ] ) ; do
  sleep 1
  counter=$((counter+1))
done

echo Verifying vagrant is up...
vagrant up
vagrant ssh -c "uptime"
echo Vagrant is up.
