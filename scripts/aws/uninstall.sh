#!/bin/bash

nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r .[0].EnclaveID) >/dev/null 2>&1
kill -9 $(ps -ef | grep vsockpx | grep -v 'grep' | awk '{print $2}') >/dev/null 2>&1

rm /usr/bin/vsockpx
rm -r /etc/uid2operator
rm -r /opt/uid2operator
rm /etc/systemd/system/uid2operator.service
