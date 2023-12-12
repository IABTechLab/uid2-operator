#!/usr/bin/env bash

date="$(date '+%Y-%m-%d')"
full_ts="$(date '+%Y-%m-%dT%H.%M.%SZ')"
delta_file="optout-delta-000_${full_ts}_64692b14.dat"

aws s3 --endpoint-url http://localhost:5001 mb s3://test-optout-bucket
aws s3 --endpoint-url http://localhost:5001 cp /s3/optout/optout-v2/delta/2023-01-01/ s3://test-optout-bucket/optout-v2/delta/2023-01-01/ --recursive
aws s3 --endpoint-url http://localhost:5001 cp /s3/optout/optout-v2/delta/optout-delta-000.dat "s3://test-optout-bucket/optout-v2/delta/${date}/${delta_file}"