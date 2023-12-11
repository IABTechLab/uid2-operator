set -ex

# Prepare conf files

ROOT="."
CORE_CONFIG_FILE_DIR="$ROOT/docker/uid2-core/conf"
OPTOUT_CONFIG_FILE_DIR="$ROOT/docker/uid2-optout/conf"

if [ -z "$CORE_ROOT" ]; then
  echo "CORE_ROOT can not be empty"
  exit 1
fi

if [ -z "$OPTOUT_ROOT" ]; then
  echo "$OPTOUT_ROOT can not be empty"
  exit 1
fi

mkdir -p "$CORE_CONFIG_FILE_DIR" && cp "$CORE_ROOT/conf/core/local-e2e-docker-config.json" "$CORE_CONFIG_FILE_DIR"
mkdir -p "$OPTOUT_CONFIG_FILE_DIR" && cp "$OPTOUT_ROOT/conf/optout/local-e2e-docker-config.json" "$OPTOUT_CONFIG_FILE_DIR"


CORE_CONFIG_FILE="$ROOT/docker/uid2-core/conf/local-e2e-docker-config.json"
OPTOUT_CONFIG_FILE="$ROOT/docker/uid2-optout/conf/local-e2e-docker-config.json"
COMPOSE_FILE="$ROOT/docker-compose.yml"
OPTOUT_MOUNT="$ROOT/docker/uid2-optout/mount"


source "$ROOT/jq_helper.sh"
source "$ROOT/healthcheck.sh"

if [ -z "$CORE_VERSION" ]; then
  echo "CORE_VERSION can not be empty"
  exit 1
fi

if [ -z "$OPTOUT_VERSION" ]; then
  echo "OPTOUT_VERSION can not be empty"
  exit 1
fi

if [ -z "$OPERATOR_VERSION" ]; then
  echo "OPERATOR_VERSION can not be empty"
  exit 1
fi

# replace placeholders
sed -i.bak "s#<CORE_VERSION>#$CORE_VERSION#g" $COMPOSE_FILE
sed -i.bak "s#<OPTOUT_VERSION>#$OPTOUT_VERSION#g" $COMPOSE_FILE
sed -i.bak "s#<OPERATOR_VERSION>#$OPERATOR_VERSION#g" $COMPOSE_FILE

cat $CORE_CONFIG_FILE
cat $OPTOUT_CONFIG_FILE

mkdir -p "$OPTOUT_MOUNT" && chmod 777 "$OPTOUT_MOUNT"

docker compose -f "$ROOT/docker-compose.yml" up -d
docker ps -a
