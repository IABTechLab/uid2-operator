#!/usr/bin/env bash

ROOT="."
NGROK_TMPL_PATH="$ROOT/ngrok.yml"
NGROK_CONFIG_DIR="$HOME/.config/ngrok"
TUNNEL_URL="http://127.0.0.1:4040/api/tunnels"

if [ -z "$NGROK_TOKEN" ]; then
  echo "NGROK_TOKEN can not be empty"
  exit 1
fi

if [ "$(uname)" == "Darwin" ]; then
  echo "run in mac"
  NGROK_CONFIG_DIR="$HOME/Library/Application Support/ngrok"
fi

# install
ngrok_cmd="ngrok"
if ! which ngrok > /dev/null; then
  echo "ngrok not found!"
  wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
  unzip -qq ngrok-stable-linux-amd64.zip
  ngrok_cmd="./ngrok"
fi

# update config file
sed -i.bak "s/<TOKEN>/$NGROK_TOKEN/g" $NGROK_TMPL_PATH

mkdir -p "$NGROK_CONFIG_DIR" && cp "$NGROK_TMPL_PATH" "$NGROK_CONFIG_DIR"

# start and check endpoint
$ngrok_cmd start --all > /dev/null &

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
