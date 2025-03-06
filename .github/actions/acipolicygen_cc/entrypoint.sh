#!/bin/sh -l

az confcom acipolicygen $@ >> /tmp/output.txt

if [[ $? -ne 0 ]]; then
    exit $?
fi

export GITHUB_OUTPUT=`cat /tmp/output.txt`

echo $GITHUB_OUTPUT
