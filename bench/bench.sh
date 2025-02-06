#!/bin/bash

cleanup() {
    echo -e "\n------- Closing all processes -------\n"
    for PID in $PID1 $PID2 $PID3; do
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
        fi
    done
    exit 0
}

trap cleanup SIGINT SIGTERM

wait_for_port_open() {
    local PORT=$1
    echo "Waiting port $PORT to be open"
    until ss -tulwn | grep ":$PORT" > /dev/null; do
        sleep 0.1
    done
    echo "Port $PORT - listening"
}

iperf3 -s -1 -i 0 &
PID1=$!

wait_for_port_open 5201;

cargo run --release --example server -- --listen-addr 127.0.0.1:1337 no-auth &
PID2=$!

wait_for_port_open 1337;

echo -e "\n------- bench client -> server -------\n"
proxychains iperf3 -c 127.0.0.1 -P 4 -i 0

iperf3 -s -1 -i 0 &
PID3=$!

wait_for_port_open 5201;

echo -e "\n------- bench server -> client -------\n"
proxychains iperf3 -c 127.0.0.1 -P 4 -R -i 0

cleanup
