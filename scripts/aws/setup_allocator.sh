#!/bin/bash

ENCLAVE_CPU_COUNT=$1
ENCLAVE_MEMORY_MIB=$2

if [ -z "$ENCLAVE_CPU_COUNT" ] || [ -z "$ENCLAVE_MEMORY_MIB" ]; then
  echo 'Need arguments: this.sh <cpu_count> <memory_mib>'
  exit 1
fi

cp allocator.template.yaml allocator.yaml
sed -i "s/^\s*memory_mib.*$/memory_mib: $ENCLAVE_MEMORY_MIB/g" allocator.yaml
sed -i "s/^\s*cpu_count.*$/cpu_count: $ENCLAVE_CPU_COUNT/g" allocator.yaml
mv allocator.yaml /etc/nitro_enclaves/

systemctl restart nitro-enclaves-allocator.service
