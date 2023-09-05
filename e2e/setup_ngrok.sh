#!/usr/bin/env bash
set -ex

ROOT="."
NGROK_TMPL_PATH="$ROOT/ngrok.yml"
TUNNEL_URL="http://127.0.0.1:4040/api/tunnels"

if [ -z "$NGROK_TOKEN" ]; then
  echo "NGROK_TOKEN can not be empty"
  exit 1
fi

# install
ngrok_cmd="ngrok"
if ! which ngrok > /dev/null; then
  echo "ngrok not found!"
  wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
  tar xvzf ngrok-v3-stable-linux-amd64.tgz
  ngrok_cmd="./ngrok"
fi

# update config file
sed -i.bak "s/<TOKEN>/$NGROK_TOKEN/g" $NGROK_TMPL_PATH

# start and check endpoint
$ngrok_cmd --config $NGROK_TMPL_PATH start --all > /dev/null &

source "$ROOT/healthcheck.sh"
healthcheck $TUNNEL_URL

# parse public url
tunnel_info=$(curl -s $TUNNEL_URL)

echo $tunnel_info

NGROK_URL_LOCALSTACK=$(jq -r '.tunnels | .[] | select(.name=="localstack") | .public_url' <<< "$tunnel_info")
NGROK_URL_CORE=$(jq -r '.tunnels | .[] | select(.name=="core") | .public_url' <<< "$tunnel_info")
NGROK_URL_OPTOUT=$(jq -r '.tunnels | .[] | select(.name=="optout") | .public_url' <<< "$tunnel_info")

# export to Github output
echo "NGROK_URL_LOCALSTACK=$NGROK_URL_LOCALSTACK"
echo "NGROK_URL_CORE=$NGROK_URL_CORE"
echo "NGROK_URL_OPTOUT=$NGROK_URL_OPTOUT"

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "NGROK_URL_LOCALSTACK=$NGROK_URL_LOCALSTACK" >> $GITHUB_OUTPUT
  echo "NGROK_URL_CORE=$NGROK_URL_CORE" >> $GITHUB_OUTPUT
  echo "NGROK_URL_OPTOUT=$NGROK_URL_OPTOUT" >> $GITHUB_OUTPUT
fi
