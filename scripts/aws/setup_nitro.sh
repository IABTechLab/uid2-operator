#!/bin/bash

amazon-linux-extras install aws-nitro-enclaves-cli -y
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service
systemctl start docker
systemctl enable docker
