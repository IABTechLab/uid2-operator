#!/bin/sh -l

az confcom acipolicygen \
    --approve-wildcards \
    --template-file \
    $GITHUB_WORKSPACE/$1 \
    --print-policy \
    >> $GITHUB_WORKSPACE/$2

# if [[ $? -ne 0 ]]; then
#     exit 1
# fi

# export GITHUB_OUTPUT=`cat /tmp/output.txt`

# echo $GITHUB_OUTPUT
