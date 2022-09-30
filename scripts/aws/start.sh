#!/bin/bash

echo "$HOSTNAME" > /etc/uid2operator/HOSTNAME
EIF_PATH=${EIF_PATH:-/opt/uid2operator/uid2operator.eif}
CID=${CID:-42}
AWS_REGION_NAME=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document/ | jq -r '.region')
if [ "$IDENTITY_SCOPE" = 'UID2' ]; then
  UID2_CONFIG_SECRET_KEY=$([[ "$(curl -s http://169.254.169.254/latest/user-data | grep UID2_CONFIG_SECRET_KEY=)" =~ ^export\ UID2_CONFIG_SECRET_KEY=\"(.*)\" ]] && echo ${BASH_REMATCH[1]} || echo "uid2-operator-config-key")
elif [ "$IDENTITY_SCOPE" = 'EUID' ]; then
  UID2_CONFIG_SECRET_KEY=$([[ "$(curl -s http://169.254.169.254/latest/user-data | grep EUID_CONFIG_SECRET_KEY=)" =~ ^export\ EUID_CONFIG_SECRET_KEY=\"(.*)\" ]] && echo ${BASH_REMATCH[1]} || echo "euid-operator-config-key")
else
  echo "Unrecognized IDENTITY_SCOPE $IDENTITY_SCOPE"
  exit 1
fi


function terminate_old_enclave() {
    ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    [ "$ENCLAVE_ID" != "null" ] && nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}
}

function config_aws() {
    aws configure set default.region $AWS_REGION_NAME
}

function default_cpu() {
    target=$(( $(nproc) * 3 / 4 ))
    if [ $target -lt 2 ]; then
        target="2"
    fi
    echo $target
}

function default_mem() {
    target=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') * 3 / 4000 ))
    if [ $target -lt 24576 ]; then
        target="24576"
    fi
    echo $target
}

function read_allocation() {
    USER_CUSTOMIZED=$(aws secretsmanager get-secret-value --secret-id "$UID2_CONFIG_SECRET_KEY" | jq -r '.SecretString' | jq -r '.customize_enclave')
    shopt -s nocasematch
    if [ "$USER_CUSTOMIZED" = "true" ]; then
        echo "Applying user customized CPU/Mem allocation..."
        CPU_COUNT=${CPU_COUNT:-$(aws secretsmanager get-secret-value --secret-id "$UID2_CONFIG_SECRET_KEY" | jq -r '.SecretString' | jq -r '.enclave_cpu_count')}
        MEMORY_MB=${MEMORY_MB:-$(aws secretsmanager get-secret-value --secret-id "$UID2_CONFIG_SECRET_KEY" | jq -r '.SecretString' | jq -r '.enclave_memory_mb')}
    else
        echo "Applying default CPU/Mem allocation..."
        CPU_COUNT=6
        MEMORY_MB=24576
    fi
    shopt -u nocasematch
}

function update_allocation() {
    ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
    if [ -z "$CPU_COUNT" ] || [ -z "$MEMORY_MB" ]; then
        echo 'No CPU_COUNT or MEMORY_MB set, cannot start enclave'
        exit 1
    fi
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

function setup_aws_proxy() {
    # allow vsock-proxy to forward to secretsmanager
    AWS_VSOCK_CFG=/etc/nitro_enclaves/vsock-proxy.yaml
    found_line=$(grep "secretsmanager.$AWS_REGION_NAME.amazonaws.com" $AWS_VSOCK_CFG | grep "port: 443" | wc -l)
    if [ "$found_line" == "0" ]; then
        echo "- {address: secretsmanager.$AWS_REGION_NAME.amazonaws.com, port: 443}" >> $AWS_VSOCK_CFG
    fi

    nohup vsock-proxy 3308 secretsmanager.$AWS_REGION_NAME.amazonaws.com 443 &
}

function run_enclave() {
    echo "starting enclave..."
    nitro-cli run-enclave --eif-path $EIF_PATH --memory $MEMORY_MB --cpu-count $CPU_COUNT --enclave-cid $CID --enclave-name uid2operator
}

terminate_old_enclave
config_aws
read_allocation
# update_allocation
setup_vsockproxy
setup_aws_proxy
setup_dante
run_enclave

echo "Done!"
