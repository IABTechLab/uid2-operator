#!/usr/bin/env bash

# for string
# https://jqlang.github.io/jq/manual/
# --arg foo 123 will bind $foo to "123".
function jq_inplace_update() {
    local file=$1
    local field=$2
    local value=$3
    jq --arg v "$value" ".$field = \$v" "$file" > tmp.json && mv tmp.json "$file"
}

# for number/boolean
# https://jqlang.github.io/jq/manual/
# --argjson foo 123 will bind $foo to 123.
function jq_inplace_update_json() {
    local file=$1
    local field=$2
    local value=$3
    jq --argjson v "$value" ".$field = \$v" "$file" > tmp.json && mv tmp.json "$file"
}
