#!/usr/bin/env bash

function jq_inplace_update() {
    local file=$1
    local field=$2
    local value=$3
    jq --arg v "$value" ".$field = \$v" "$file" > tmp.json && mv tmp.json "$file"
}

function jq_inplace_update_json() {
    local file=$1
    local field=$2
    local value=$3
    jq --argjson v "$value" ".$field = \$v" "$file" > tmp.json && mv tmp.json "$file"
}