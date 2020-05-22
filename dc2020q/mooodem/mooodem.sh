#!/bin/bash
HOST=$1
PORT=$2
./minimodem -t 1200 --float-samples -R 48000 -q -f - | \
socat tcp:$HOST:$PORT - | \
./minimodem -r 1200 --float-samples -R 48000 -q -f -

