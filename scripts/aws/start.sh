#!/bin/bash

echo "$HOSTNAME" > /etc/uid2operator/HOSTNAME
EIF_PATH=${EIF_PATH:-/opt/uid2operator/uid2operator.eif}
CID=${CID:-42}
CPU_COUNT=${CPU_COUNT:-$(curl -s http://169.254.169.254/latest/user-data | jq -r '.enclave_cpu_count')}
MEMORY_MB=${MEMORY_MB:-$(curl -s http://169.254.169.254/latest/user-data | jq -r '.enclave_memory_mb')}

if [ -z "$CPU_COUNT" ] || [ -z "$MEMORY_MB" ]; then
    echo 'No CPU_COUNT or MEMORY_MB set, cannot start enclave'
    exit 1
fi

function terminate_old_enclave() {
    ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    [ "$ENCLAVE_ID" != "null" ] && nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}
}

function update_allocation() {
    ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
    echo "updating allocator: CPU_COUNT=$CPU_COUNT, MEMORY_MB=$MEMORY_MB..."
    systemctl stop nitro-enclaves-allocator.service
    sed -r "s/^(\s*memory_mib\s*:\s*).*/\1$MEMORY_MB/" -i $ALLOCATOR_YAML
    sed -r "s/^(\s*cpu_count\s*:\s*).*/\1$CPU_COUNT/" -i $ALLOCATOR_YAML
    systemctl start nitro-enclaves-allocator.service && systemctl enable nitro-enclaves-allocator.service
    echo "nitro-enclaves-allocator restarted"   
}

function setup_vsockproxy() {
    VSOCK_PROXY=${VSOCK_PROXY:-/usr/bin/vsockpx}
    VSOCK_CONFIG=${VSOCK_CONFIG:-/etc/uid2operator/proxy.yaml}
    VSOCK_THREADS=${VSOCK_THREADS:-$(( $(nproc) * 2 )) }
    VSOCK_LOG_LEVEL=${VSOCK_LOG_LEVEL:-3}
    echo "starting vsock proxy at $VSOCK_PROXY with $VSOCK_THREADS worker threads..."
    $VSOCK_PROXY -c $VSOCK_CONFIG --workers $VSOCK_THREADS --log-level $VSOCK_LOG_LEVEL --daemon
    echo "vsock proxy now running in background."
}

function setup_dante() {
    sockd -D
}

function run_enclave() {
    echo "starting enclave..."
    nitro-cli run-enclave --eif-path $EIF_PATH --memory $MEMORY_MB --cpu-count $CPU_COUNT --enclave-cid $CID
}

terminate_old_enclave
update_allocation
setup_vsockproxy
setup_dante
run_enclave

echo "Done!"
