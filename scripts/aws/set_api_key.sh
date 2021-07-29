#!/bin/bash

if [ -z "$1" ]; then
  echo 'empty argument: api_key'
  exit 1
fi

cp /etc/uid2operator/config.json .
cat <<< $(jq ".core_api_token = \"$1\"" config.json) > config.json
cat <<< $(jq ".optout_api_token = \"$1\"" config.json) > config.json
cp config.json /etc/uid2operator/
