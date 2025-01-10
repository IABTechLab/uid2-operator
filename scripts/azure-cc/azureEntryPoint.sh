#!/bin/sh
#
# This script must be compatible with Ash (provided in eclipse-temurin Docker image) and Bash

echo "-- starting azureEntryPoint.py check"

if ! python3 /app/azureEntryPoint.py; then
    echo "Error: azureEntryPoint.py failed to execute." >&2
    exit 1
fi

echo "-- azureEntryPoint.py executed successfully"
