#!/bin/bash -euf

set -o pipefail

ulimit -n 65536

# setup loopback device
echo "-- setup loopback device"
ifconfig lo 127.0.0.1

# start vsock proxy
echo "-- start vsock proxy"
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( $(nproc) * 4 )) --log-level 3

# load configurations
echo "-- load configurations"
python3 /app/load_config.py >/app/conf/config-overrides.json

# build final configurations
echo "-- build final configurations"
if [ "$IDENTITY_SCOPE" = 'UID2' ]; then
  python3 /app/make_config.py /app/conf/prod-uid2-config.json /app/conf/integ-uid2-config.json /app/conf/config-overrides.json $(nproc) >/app/conf/config-final.json
elif [ "$IDENTITY_SCOPE" = 'EUID' ]; then
  python3 /app/make_config.py /app/conf/prod-euid-config.json /app/conf/integ-euid-config.json /app/conf/config-overrides.json $(nproc) >/app/conf/config-final.json
else
  echo "Unrecognized IDENTITY_SCOPE $IDENTITY_SCOPE"
  exit 1
fi

get_config_value() {
  jq -r ".\"$1\"" /app/conf/config-final.json
}

# setup loki
echo "-- setup loki"
[[ "$(get_config_value 'loki_enabled')" == "true" ]] \
  && SETUP_LOKI_LINE="-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory -Dlogback.configurationFile=./conf/logback.loki.xml" \
  || SETUP_LOKI_LINE=""

# retrieve hostname from node - will not work for multiple enclaves per node
echo "-- retrieve hostname"
HOSTNAME=$(curl -s "http://127.0.0.1:27015/operator/hostname")
echo "HOSTNAME=$HOSTNAME"

# -- set pwd to /app so we can find default configs
cd /app

echo "-- starting java application"
# -- starting java application
java \
  -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
  -Djava.security.egd=file:/dev/./urandom \
  -Djava.library.path=/app/lib \
  -Dvertx-config-path=/app/conf/config-final.json \
  $SETUP_LOKI_LINE \
  -Dhttp_proxy=socks5://127.0.0.1:3305 \
  -jar /app/$JAR_NAME-$JAR_VERSION.jar
