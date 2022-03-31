#!/bin/bash

nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
kill -9 $(ps -ef | grep vsockpx | grep -v 'grep' | awk '{print $2}')
kill -9 $(ps -ef | grep sockd | grep -v 'grep' | awk '{print $2}')