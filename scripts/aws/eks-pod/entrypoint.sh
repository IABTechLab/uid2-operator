#!/bin/bash -eufx
CID=42
EIF_PATH=/home/uid2operator.eif
MEMORY_MB=24576
CPU_COUNT=6

set -x

function terminate_old_enclave() {
    echo "terminate_old_enclave"
    nitro-cli describe-enclaves
    ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    if [ "$ENCLAVE_ID" != "null" ]; then
        nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}
        echo "Terminated enclave with ID ${ENCLAVE_ID}"
    else
        echo "No running enclaves to terminate."
    fi

    nitro-cli terminate-enclave --all
}

function debug() {
    ps aux
    ip link show
    ifconfig
}

function setup_vsockproxy() {
    echo "setup_vsockproxy"
    VSOCK_PROXY=${VSOCK_PROXY:-/home/vsockpx}
    VSOCK_CONFIG=${VSOCK_CONFIG:-/home/proxies.host.yaml}
    VSOCK_THREADS=${VSOCK_THREADS:-$(( $(nproc) * 2 )) }
    VSOCK_LOG_LEVEL=${VSOCK_LOG_LEVEL:-3}
    echo "starting vsock proxy at $VSOCK_PROXY with $VSOCK_THREADS worker threads..."
    $VSOCK_PROXY -c $VSOCK_CONFIG --workers $VSOCK_THREADS --log-level $VSOCK_LOG_LEVEL --daemon
    echo "vsock proxy now running in background."
}

function setup_dante() {
    echo "setup_dante"
    ulimit -n 1024
    /home/sockd -D
}

function start_syslog() {
    /usr/sbin/syslog-ng --no-caps
}

function run_config_server() {
    echo "run_config_server"
    cd /home/config-server/
    /config-server/bin/flask run --host 127.0.0.1 --port 27015 &
    sleep 5
}

function wait_for_config() {
    RETRY_COUNT=0
    MAX_RETRY=20
    while true; do
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:27015/getConfig)
        if [ "$RESPONSE" -eq "200" ]; then
            echo "Config server running"
            break;
        else
            echo "Config server still starting..."
        fi
        RETRY_COUNT=$(( RETRY_COUNT + 1))
        if [ $RETRY_COUNT -gt $MAX_RETRY ]; then
            echo "Config Server did not start. Exiting"
            exit 1
        fi
        sleep 5
    done
}

function update_config() {
    { set +x; } 2>/dev/null; { IDENTITY_SERVICE_CONFIG=$(curl -s http://127.0.0.1:27015/getConfig); set -x; }
    if jq -e . >/dev/null 2>&1 <<<"${IDENTITY_SERVICE_CONFIG}"; then
        echo "Identity service returned valid config"
    else
        echo "Failed to get a valid config from identity service"
        exit 1
    fi

    shopt -s nocasematch
    { set +x; } 2>/dev/null; { USER_CUSTOMIZED=$(echo $IDENTITY_SERVICE_CONFIG | jq -r '.customize_enclave'); set -x; }

    if [ "$USER_CUSTOMIZED" = "true" ]; then
        echo "Applying user customized CPU/Mem allocation..."
        { set +x; } 2>/dev/null; { CPU_COUNT=$(echo $IDENTITY_SERVICE_CONFIG | jq -r '.enclave_cpu_count'); set -x; }
        { set +x; } 2>/dev/null; { MEMORY_MB=$(echo $IDENTITY_SERVICE_CONFIG | jq -r '.enclave_memory_mb'); set -x; }
    fi
    shopt -u nocasematch
}

function run_enclave() {
    echo "starting enclave... --cpu-count $CPU_COUNT --memory $MEMORY_MB --eif-path $EIF_PATH --enclave-cid $CID"
    nitro-cli terminate-enclave --all
    nitro-cli run-enclave --cpu-count $CPU_COUNT --memory $MEMORY_MB --eif-path $EIF_PATH --enclave-cid $CID --enclave-name uid2-operator --debug-mode --attach-console

    echo "Show log files..."
    cat /var/log/nitro_enclaves/*.log
}

echo "starting ..."
terminate_old_enclave
echo "terminated old enclaves"

echo "starting syslog-ng"
start_syslog
echo "started syslog-ng"

debug
setup_vsockproxy
setup_dante
run_config_server
wait_for_config
update_config
run_enclave

sleep 60s
set +x
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
while [ "$ENCLAVE_ID" != "null" ];
do
  ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
  sleep 10s
done;

echo "No running enclave, so shutting down the pod"
