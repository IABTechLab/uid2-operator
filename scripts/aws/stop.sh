#!/bin/bash

function terminate_old_enclave() {
    echo "Terminating Enclave..."
    ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    if [ "$ENCLAVE_ID" != "null" ]; then
        nitro-cli terminate-enclave --enclave-id $ENCLAVE_ID
    else
        echo "no running enclaves to terminate"
    fi
}

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

terminate_old_enclave
kill_process vsockpx
kill_process sockd

echo "Done!"
