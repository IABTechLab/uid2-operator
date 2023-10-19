#!/usr/bin/env bash
set -ex

ROOT="."
METADATA_ROOT="$ROOT/docker/localstack/s3/core"
OPERATOR_FILE="$METADATA_ROOT/operators/operators.json"
ENCLAVE_FILE="$METADATA_ROOT/enclaves/enclaves.json"

if [[ ! -f $OUTPUT_POLICY_DIGEST_FILE ]]; then
  echo "OUTPUT_POLICY_DIGEST_FILE does not exist"
  exit 1
fi

AZURE_CC_POLICY_DIGEST="$(cat $OUTPUT_POLICY_DIGEST_FILE)"

echo "AZURE_CC_POLICY_DIGEST=$AZURE_CC_POLICY_DIGEST"

enclave_id=$AZURE_CC_POLICY_DIGEST

# fetch operator key
OPERATOR_KEY=$(jq -r '.[] | select(.protocol=="azure-cc") | .key' $OPERATOR_FILE)

# update azure-cc enclave id
cat <<< $(jq '(.[] | select(.protocol=="azure-cc") | .identifier) |='\"$enclave_id\"'' $ENCLAVE_FILE) > $ENCLAVE_FILE

# export to Github output
echo "OPERATOR_KEY=$OPERATOR_KEY"

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "OPERATOR_KEY=$OPERATOR_KEY" >> $GITHUB_OUTPUT
fi
