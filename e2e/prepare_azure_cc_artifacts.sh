#!/usr/bin/env bash
set -ex

mkdir -p AZURE_OUTPUT_DIR

# TODO: generate artifacts to azure-artifacts folder

AZURE_CC_POLICY_DIGEST="$(cat $AZURE_OUTPUT_DIGEST)"

echo "AZURE_CC_POLICY_DIGEST=$AZURE_CC_POLICY_DIGEST"
