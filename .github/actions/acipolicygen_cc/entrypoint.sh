#!/bin/sh -l

az confcom acipolicygen \
    --approve-wildcards \
    --template-file \
    $GITHUB_WORKSPACE/$1 \
    --print-policy \
    >> /tmp/output.txt

if [[ $? -ne 0 ]]; then
    exit 1
fi

export GITHUB_OUTPUT=`cat /tmp/output.txt`

echo $GITHUB_OUTPUT
