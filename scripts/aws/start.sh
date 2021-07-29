#!/bin/bash

echo "$HOSTNAME" > /etc/uid2operator/HOSTNAME

EIF_PATH=${EIF_PATH:-/opt/uid2operator/uid2operator.eif}
CPU_COUNT=${CPU_COUNT:-$(curl -s http://169.254.169.254/latest/user-data | jq -r '.enclave_cpu_count')}
MEMORY_MB=${MEMORY_MB:-$(curl -s http://169.254.169.254/latest/user-data | jq -r '.enclave_memory_mb')}
CID=${CID:-42}
VSOCK_PROXY=${VSOCK_PROXY:-/usr/bin/vsockpx}
VSOCK_CONFIG=${VSOCK_CONFIG:-/etc/uid2operator/proxy.yaml}
VSOCK_THREADS=${VSOCK_THREADS:-$(nproc)}
VSOCK_LOG_LEVEL=${VSOCK_LOG_LEVEL:-3}

if [ -z "$CPU_COUNT" ] || [ -z "$MEMORY_MB" ]; then
  echo 'No CPU_COUNT or MEMORY_MB set, cannot start enclave'
  exit 1
fi

echo "updating allocator: CPU_COUNT=$CPU_COUNT, MEMORY_MB=$MEMORY_MB..."
cp /etc/uid2operator/allocator.template.yaml /etc/nitro_enclaves/allocator.yaml
sed -i "s/^\s*memory_mib.*$/memory_mib: $MEMORY_MB/g" /etc/nitro_enclaves/allocator.yaml
sed -i "s/^\s*cpu_count.*$/cpu_count: $CPU_COUNT/g" /etc/nitro_enclaves/allocator.yaml
systemctl restart nitro-enclaves-allocator.service
echo "nitro-enclaves-allocator restarted"

echo "starting vsock proxy at $VSOCK_PROXY with $VSOCK_THREADS worker threads..."
$VSOCK_PROXY -c $VSOCK_CONFIG --num-threads $VSOCK_THREADS --log-level $VSOCK_LOG_LEVEL --daemon
echo "vsock proxy now running in background."

echo "starting enclave..."
nitro-cli run-enclave --eif-path $EIF_PATH --memory $MEMORY_MB --cpu-count $CPU_COUNT --enclave-cid $CID
echo "Done!"