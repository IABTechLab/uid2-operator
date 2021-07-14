SCRIPT_DIR=./scripts/aws
BUILD_DIR=./build
DEPENDENCY_DIR=./dependencies

STARTSH=$(SCRIPT_DIR)/start.sh
STOPSH=$(SCRIPT_DIR)/stop.sh
EIF=$(BUILD_DIR)/uid2operator.eif
SERVICE=$(SCRIPT_DIR)/uid2operator.service
ALLOCATOR_TEMPLATE=$(PROJECT_DIR)/allocator.template.yaml
VSOCKPX=$(DEPENDENCY_DIR)/vsockpx
HOST_PROXY_CFG=$(SCRIPT_DIR)/proxies.host.yaml
ENCL_PROXY_CFG=$(SCRIPT_DIR)/proxies.nitro.yaml

.PHONY: all
all: build-eif

install: $(PROJECT_DIR)/start.sh $(PROJECT_DIR)/stop.sh $(PROJECT_DIR)/uid2operator.service $(PROJECT_DIR)/uid2operator.eif $(PROJECT_DIR)/allocator.template.yaml $(PROJECT_DIR)/proxies.host.yaml
	mkdir -p /etc/uid2operator
	mkdir -p /opt/uid2operator
	cp $(PROJECT_DIR)/dependencies/vsockpx /usr/bin/
	chmod +x /usr/bin/vsockpx
	cp $(PROJECT_DIR)/proxies.host.yaml /etc/uid2operator/proxy.yaml
	cp $(PROJECT_DIR)/allocator.template.yaml /etc/uid2operator/
	cp $(PROJECT_DIR)/uid2operator.eif /etc/uid2operator/
	cp 


build/start.sh: build_dir ./scripts/aws/start.sh
	cp ./scripts/aws/start.sh ./build/

build/stop.sh: build_dir ./scripts/aws/stop.sh
	cp ./scripts/aws/stop.sh ./build/

build/allocator.template.yaml: build_dir ./scripts/aws/allocator.template.yaml
	cp ./scripts/aws/allocator.template.yaml ./build/

build/proxies.host.yaml: build_dir ./scripts/aws/proxies.host.yaml
	cp ./scripts/aws/proxies.host.yaml ./build/

build/uid2operator.service: build_dir ./scripts/aws/uid2operator.service
	cp ./scripts/aws/uid2operator.service ./build/

build/vsockpx: setup_dependencies ./dependencies/vsockpx

build_dir:
	$(shell test -d build || mkdir build)

setup_dependencies: 
	GITHUB_ACCESS_TOKEN=$(GITHUB_ACCESS_TOKEN) enclave_platform="aws-nitro" ./setup_dependencies.sh