#!/bin/sh

echo "Checking for our certs..."

# Wait for the CA certificate to be generated
while [ ! -f /certs/provisioned ]
do
  echo "Certs not ready. Waiting for /certs/provisioned..."
  sleep 1
done

echo "Certs are ready. Starting service:" "$@"

# Start the service
exec "$@"
