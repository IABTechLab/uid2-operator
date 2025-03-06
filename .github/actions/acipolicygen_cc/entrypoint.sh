#!/bin/sh -l

POLICY_BASE_64=$(az confcom acipolicygen \
    --approve-wildcards \
    --template-file \
    $GITHUB_WORKSPACE/$1 \
    --print-policy)

if [[ $? -ne 0 ]]; then
    exit 1
fi

echo "policy=${POLICY_BASE_64}" >> "$GITHUB_OUTPUT"

# export GITHUB_OUTPUT=`cat /tmp/output.txt`

# echo $GITHUB_OUTPUT
