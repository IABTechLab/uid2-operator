#!/bin/bash -xe

DOCKERIMAGE="$1"

if [ x$DOCKERIMAGE = x ]; then
	echo "Usage $0 <docker_image_name_and_tag>"
	exit
fi

# Switch to the root source folder
PROJPATH="$( cd -- "$(dirname "$0")/../.." >/dev/null 2>&1 ; pwd -P )"
cd $PROJPATH

export enclave_platform=gcp-vmid
./setup_dependencies.sh
mvn package -P gcp
docker build --build-arg JAR_VERSION=1.0.0 -t ${DOCKERIMAGE} -f Dockerfile .

echo New docker image is successfully built ${DOCKERIMAGE}
echo To push to container registry, you can run: docker push ${DOCKERIMAGE}
