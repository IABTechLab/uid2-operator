#!/bin/bash -euf -o pipefail

ulimit -n 65536

# setup loopback device
ifconfig lo 127.0.0.1

# -- start vsock proxy
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( $(nproc) * 2 )) --log-level 3

# -- load config via proxy
export UID2_CONFIG_SECRET_KEY=${UID2_CONFIG_SECRET_KEY:-"uid2-operator-config-key"}
export AWS_REGION_NAME=$(curl -s -x socks5h://127.0.0.1:3305 http://169.254.169.254/latest/dynamic/instance-identity/document/ | jq -r '.region')
IAM_ROLE=$(curl -s -x socks5h://127.0.0.1:3305 http://169.254.169.254/latest/meta-data/iam/security-credentials/)
echo "IAM_ROLE=$IAM_ROLE"
CREDS_ENDPOINT="http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE"
export AWS_ACCESS_KEY_ID=$(curl -s -x socks5h://127.0.0.1:3305 $CREDS_ENDPOINT | jq -r '.AccessKeyId')
export AWS_SECRET_KEY=$(curl -s -x socks5h://127.0.0.1:3305 $CREDS_ENDPOINT | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(curl -s -x socks5h://127.0.0.1:3305 $CREDS_ENDPOINT | jq -r '.Token')
echo "UID2_CONFIG_SECRET_KEY=$UID2_CONFIG_SECRET_KEY"
echo "AWS_REGION_NAME=$AWS_REGION_NAME"
echo "127.0.0.1 secretsmanager.$AWS_REGION_NAME.amazonaws.com" >> /etc/hosts

python3 /app/load_config.py >/app/conf/config-overrides.json
python3 /app/make_config.py /app/conf/config.json /app/conf/config-overrides.json $(nproc) >/app/conf/config-final.json

get_config_value() {
  jq -r ".\"$1\"" /app/conf/config-final.json
}

echo "-- setup loki"
[[ "$(get_config_override 'loki_enabled')" == "true" ]] \
  && SETUP_LOKI_LINE="-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory -Dlogback.configurationFile=./conf/logback.loki.xml" \
  || SETUP_LOKI_LINE=""

HOSTNAME=$(curl -s -x socks5h://127.0.0.1:3305 http://169.254.169.254/latest/meta-data/local-hostname)
echo "HOSTNAME=$HOSTNAME"

# -- set pwd to /app so we can find default configs
cd /app

echo "-- starting java application"
# -- start operator
java \
  -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
  -Djava.security.egd=file:/dev/./urandom \
  -Djava.library.path=/app/lib \
  -Dvertx-config-path=/app/conf/config-final.json \
  $SETUP_LOKI_LINE \
  -Dhttp_proxy=socks5://127.0.0.1:3305 \
  -jar /app/$JAR_NAME-$JAR_VERSION.jar
