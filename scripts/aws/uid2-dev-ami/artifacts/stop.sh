#!/bin/bash

function kill_process() {
    echo "Shutting down $1..."
    pid=$(pidof $1)
    if [ -z "$pid" ]; then
        echo "process $1 not found"
    else
        kill -9 $pid
        echo "$1 exited"
    fi
}

kill_process vsockpx
kill_process sockd
kill_process nohup

echo "Done!"
