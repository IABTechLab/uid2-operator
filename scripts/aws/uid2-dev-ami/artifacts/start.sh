#!/bin/bash

echo "$HOSTNAME" > /etc/uid2operator/HOSTNAME
IDENTITY_SCOPE=${IDENTITY_SCOPE:-$(cat /opt/uid2operator/identity_scope.txt)}
CID=${CID:-42}
TOKEN=$(curl --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600")
USER_DATA=$(curl -s http://169.254.169.254/latest/user-data --header "X-aws-ec2-metadata-token: $TOKEN")
AWS_REGION_NAME=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document/ --header "X-aws-ec2-metadata-token: $TOKEN" | jq -r '.region')
if [ "$IDENTITY_SCOPE" = 'UID2' ]; then
  UID2_CONFIG_SECRET_KEY=$([[ "$(echo "${USER_DATA}" | grep UID2_CONFIG_SECRET_KEY=)" =~ ^export\ UID2_CONFIG_SECRET_KEY=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "uid2-operator-config-key")
elif [ "$IDENTITY_SCOPE" = 'EUID' ]; then
  UID2_CONFIG_SECRET_KEY=$([[ "$(echo "${USER_DATA}" | grep EUID_CONFIG_SECRET_KEY=)" =~ ^export\ EUID_CONFIG_SECRET_KEY=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "euid-operator-config-key")
else
  echo "Unrecognized IDENTITY_SCOPE $IDENTITY_SCOPE"
  exit 1
fi
API_KEY=$([[ "$(echo "${USER_DATA}" | grep API_KEY=)" =~ ^export\ API_KEY=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "")
ENVIRONMENT=$([[ "$(echo "${USER_DATA}" | grep ENVIRONMENT=)" =~ ^export\ ENVIRONMENT=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "")
CORE_BASE_URL=$([[ "$(echo "${USER_DATA}" | grep CORE_BASE_URL=)" =~ ^export\ CORE_BASE_URL=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "")
OPTOUT_BASE_URL=$([[ "$(echo "${USER_DATA}" | grep OPTOUT_BASE_URL=)" =~ ^export\ OPTOUT_BASE_URL=\"(.*)\"$ ]] && echo "${BASH_REMATCH[1]}" || echo "")

echo "UID2_CONFIG_SECRET_KEY=${UID2_CONFIG_SECRET_KEY}"
echo "CORE_BASE_URL=${CORE_BASE_URL}"
echo "OPTOUT_BASE_URL=${OPTOUT_BASE_URL}"
echo "AWS_REGION_NAME=${AWS_REGION_NAME}"

function config_aws() {
    aws configure set default.region $AWS_REGION_NAME
}

function setup_vsockproxy() {
    VSOCK_PROXY=${VSOCK_PROXY:-/usr/bin/vsockpx}
    VSOCK_CONFIG=${VSOCK_CONFIG:-/etc/uid2operator/proxy.yaml}
    VSOCK_THREADS=${VSOCK_THREADS:-$(( $(nproc) * 2 )) }
    VSOCK_LOG_LEVEL=${VSOCK_LOG_LEVEL:-3}
    echo "starting vsock proxy at $VSOCK_PROXY with $VSOCK_THREADS worker threads..."
    $VSOCK_PROXY -c $VSOCK_CONFIG --workers $VSOCK_THREADS --log-level $VSOCK_LOG_LEVEL --daemon
    echo "vsock proxy now running in background."
}

function setup_dante() {
    sockd -D
}

function run_config_server() {
    mkdir -p /etc/secret/secret-value
    echo $(jq ".api_token = \"$API_KEY\"" /etc/secret/secret-value/config) > /etc/secret/secret-value/config
    echo $(jq ".environment = \"$ENVIRONMENT\"" /etc/secret/secret-value/config) > /etc/secret/secret-value/config
    echo $(jq ".core_base_url = \"$CORE_BASE_URL\"" /etc/secret/secret-value/config) > /etc/secret/secret-value/config
    echo $(jq ".optout_base_url = \"$OPTOUT_BASE_URL\"" /etc/secret/secret-value/config) > /etc/secret/secret-value/config
    cat /etc/secret/secret-value/config
    echo "run_config_server"
    cd /opt/uid2operator/config-server
    ./bin/flask run --host 127.0.0.1 --port 27015 &
}

config_aws
setup_vsockproxy
setup_dante
run_config_server

echo "Done!"
