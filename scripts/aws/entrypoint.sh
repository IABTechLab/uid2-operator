#!/bin/bash

ulimit -n 65536

# setup loopback device
ifconfig lo 127.0.0.1

# -- start vsock proxy
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( $(nproc) * 4 )) --log-level 3

user_data() {
  curl -s -x socks5h://127.0.0.1:3305 http://169.254.169.254/latest/user-data | jq -r ".\"$1\""
}

set_config() {
  key=$1
  val=$2
  typ=$(jq -r ".\"$key\"|type" /app/conf/config.json)
  if [[ "$typ" == "string" ]]; then
    cat <<< $(jq ".\"$key\" = \"$val\"" /app/conf/config.json) > /app/conf/config.json
  elif [[ "$typ" == "number" ]]; then
    cat <<< $(jq ".\"$key\" = $val" /app/conf/config.json) > /app/conf/config.json
  elif [[ "$typ" == "boolean" ]]; then
    cat <<< $(jq ".\"$key\" = $val" /app/conf/config.json) > /app/conf/config.json
  fi
}

overridable_variables=(           \
  'service_instances'             \
  'clients_metadata_path'         \
  'keys_metadata_path'            \
  'salts_metadata_path'           \
  'keys_acl_metadata_path'        \
  'core_attest_url'               \
  'optout_metadata_path'          \
  'optout_api_uri'                \
  'optout_synthetic_logs_enabled' \
  'optout_synthetic_logs_count'   \
)

echo "-- set api token"
API_TOKEN=$(user_data 'api_token')
set_config 'core_api_token' "$API_TOKEN"
set_config 'optout_api_token' "$API_TOKEN"

echo "-- override runtime configurations"
for varname in "${overridable_variables[@]}"; do
  val=$(user_data "$varname")
  if [[ -n "$val" && "$val" != "null" ]]; then
    set_config "$varname" "$val"
  fi
done

echo "-- setup loki"
[[ "$(user_data 'loki_enabled')" == "true" ]] \
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
  -Dvertx-config-path=/app/conf/config.json \
  $SETUP_LOKI_LINE \
  -Dhttp_proxy=socks5://127.0.0.1:3305 \
  -jar /app/$JAR_NAME-$JAR_VERSION.jar
