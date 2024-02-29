#!/bin/bash

PROJECT_DIR=${PROJECT_DIR:-.}

mkdir -p /etc/uid2operator
mkdir -p /opt/uid2operator

cp $PROJECT_DIR/dependencies/vsockpx /usr/bin/
chmod +x /usr/bin/vsockpx

cp $PROJECT_DIR/proxies.host.yaml       /etc/uid2operator/proxy.yaml
cp $PROJECT_DIR/allocator.template.yaml /etc/uid2operator/

cp $PROJECT_DIR/uid2operator.eif /opt/uid2operator/
cp $PROJECT_DIR/start.sh         /opt/uid2operator/
cp $PROJECT_DIR/stop.sh          /opt/uid2operator/

cp $PROJECT_DIR/uid2operator.service /etc/systemd/system/