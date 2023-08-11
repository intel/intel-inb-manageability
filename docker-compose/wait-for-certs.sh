#!/bin/sh

# Wait for the CA certificate to be generated
while [ ! -f /certs/ca.crt ]
do
  echo "Waiting for CA certificate..."
  sleep 1
done

# Start the service
exec "$@"