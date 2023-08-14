#!/bin/bash

# helps docker-compose shut down faster
trap "exit" SIGTERM SIGINT
sleep infinity &
wait
