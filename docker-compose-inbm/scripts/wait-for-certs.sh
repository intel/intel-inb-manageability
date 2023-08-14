#!/bin/sh

echo "Checking CA certs."

# Wait for the CA certificate to be generated
while [ ! -f /certs/provisioned ]
do
  echo "Waiting for /certs/provisioned..."
  sleep 1
done

# Start the service
exec "$@"