#!/usr/bin/env python3

import boto3
import json
import os
import subprocess
import re
import multiprocessing
import requests
import signal
import argparse
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict
import sys
import time
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, MissingInstanceProfile, ConfigNotFound, InvalidConfigValue, ConfidentialComputeStartupException

class AWSConfidentialComputeConfig(ConfidentialComputeConfig):
    enclave_memory_mb: int
    enclave_cpu_count: int

class AuxiliaryConfig:
    FLASK_PORT: str = "27015"
    LOCALHOST: str = "127.0.0.1"
    AWS_METADATA: str = "169.254.169.254"
    
    @classmethod
    def get_socks_url(cls) -> str:
        return f"socks5://{cls.LOCALHOST}:3306"
    
    @classmethod
    def get_config_url(cls) -> str:
        return f"http://{cls.LOCALHOST}:{cls.FLASK_PORT}/getConfig"
    
    @classmethod
    def get_user_data_url(cls) -> str:
        return f"http://{cls.AWS_METADATA}/latest/user-data"
    
    @classmethod
    def get_token_url(cls) -> str:
        return f"http://{cls.AWS_METADATA}/latest/api/token"
    
    @classmethod
    def get_meta_url(cls) -> str:
        return f"http://{cls.AWS_METADATA}/latest/dynamic/instance-identity/document"
    

class EC2(ConfidentialCompute):

    def __init__(self):
        self.configs: AWSConfidentialComputeConfig = {}


    def __get_aws_token(self) -> str:
        """Fetches a temporary AWS EC2 metadata token."""
        try:
            response = requests.put(
                AuxiliaryConfig.get_token_url(), headers={"X-aws-ec2-metadata-token-ttl-seconds": "3600"}, timeout=2
            )
            return response.text
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch AWS token: {e}")

    def __get_current_region(self) -> str:
        """Fetches the current AWS region from EC2 instance metadata."""
        token = self.__get_aws_token()
        headers = {"X-aws-ec2-metadata-token": token}
        try:
            response = requests.get(AuxiliaryConfig.get_meta_url(), headers=headers, timeout=2)
            response.raise_for_status()
            return response.json()["region"]
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch region: {e}")
        
    def __validate_aws_specific_config(self):
        if "enclave_memory_mb" in self.configs or "enclave_cpu_count" in self.configs:
            max_capacity = self.__get_max_capacity()
            min_capacity = {"enclave_memory_mb": 11000, "enclave_cpu_count" : 2 }
            for key in ["enclave_memory_mb", "enclave_cpu_count"]:
                if int(self.configs.get(key, 0)) > max_capacity.get(key):
                    raise ValueError(f"{key} value ({self.configs.get(key, 0)}) exceeds the maximum allowed ({max_capacity.get(key)}).")
                if min_capacity.get(key) > int(self.configs.get(key, 10**9)):
                    raise ValueError(f"{key} value ({self.configs.get(key, 0)}) needs to be higher than the minimum required ({min_capacity.get(key)}).")
                
    def _set_secret(self, secret_identifier: str) -> None:
        """Fetches a secret value from AWS Secrets Manager and adds defaults"""

        def add_defaults(configs: Dict[str, any]) ->  None:
            """Adds default values to configuration if missing."""
            default_capacity = self.__get_max_capacity()
            configs.setdefault("enclave_memory_mb", default_capacity["enclave_memory_mb"])
            configs.setdefault("enclave_cpu_count", default_capacity["enclave_cpu_count"])
            configs.setdefault("debug_mode", False)
        
        region = self.__get_current_region()
        print(f"Running in {region}")
        client = boto3.client("secretsmanager", region_name=region)
        try:
            add_defaults(json.loads(client.get_secret_value(SecretId=secret_identifier)["SecretString"]))
            self.__validate_aws_specific_config()
        except NoCredentialsError as _:
            raise MissingInstanceProfile(self.__class__.__name__)
        except ClientError as _:
            raise ConfigNotFound(self.__class__.__name__, f"Secret Manager {secret_identifier} in {region}")
        
    @staticmethod
    def __get_max_capacity():
        try:
            with open("/etc/nitro_enclaves/allocator.yaml", "r") as file:
                nitro_config = yaml.safe_load(file)
            return {"enclave_memory_mb": nitro_config['memory_mib'],  "enclave_cpu_count": nitro_config['cpu_count']}
        except Exception as e:
            raise RuntimeError("/etc/nitro_enclaves/allocator.yaml does not have CPU, memory allocated")

    def __setup_vsockproxy(self, log_level: int) -> None:
        """
        Sets up the vsock proxy service.
        """
        thread_count = (multiprocessing.cpu_count() + 1) // 2
        command = [
            "/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml",
            "--workers", str(thread_count), "--log-level", str(log_level), "--daemon"
        ]
        self.run_command(command)

    def __run_config_server(self) -> None:
        """
        Starts the Flask configuration server.
        """
        os.makedirs("/etc/secret/secret-value", exist_ok=True)
        config_path = "/etc/secret/secret-value/config"
        with open(config_path, 'w') as config_file:
            json.dump(self.configs, config_file)
        os.chdir("/opt/uid2operator/config-server")
        command = ["./bin/flask", "run", "--host", AuxiliaryConfig.LOCALHOST, "--port", AuxiliaryConfig.FLASK_PORT]
        self.run_command(command, seperate_process=True)

    def __run_socks_proxy(self) -> None:
        """
        Starts the SOCKS proxy service.
        """
        command = ["sockd", "-D"]
        self.run_command(command)

    def __get_secret_name_from_userdata(self) -> str:
        """Extracts the secret name from EC2 user data."""
        token = self.__get_aws_token()
        response = requests.get(AuxiliaryConfig.get_user_data_url(), headers={"X-aws-ec2-metadata-token": token})
        user_data = response.text

        with open("/opt/uid2operator/identity_scope.txt") as file:
            identity_scope = file.read().strip()

        default_name = f"{identity_scope.lower()}-operator-config-key"
        hardcoded_value = f"{identity_scope.upper()}_CONFIG_SECRET_KEY"
        match = re.search(rf'^export {hardcoded_value}="(.+?)"$', user_data, re.MULTILINE)
        return match.group(1) if match else default_name

    def _setup_auxiliaries(self) -> None:
        """Sets up the vsock tunnel, socks proxy and flask server"""
        log_level = 1 if self.configs["debug_mode"] else 3
        self.__setup_vsockproxy(log_level)
        self.__run_config_server()
        self.__run_socks_proxy()
        print("Finished setting up all auxiliaries")

    def _validate_auxiliaries(self) -> None:
        """Validates connection to flask server direct and through socks proxy."""
        print("Validating auxiliaries")
        try:
            for attempt in range(10):
                try:
                    response = requests.get(AuxiliaryConfig.get_config_url())
                    print("Config server is reachable")
                    break
                except requests.exceptions.ConnectionError as e:
                    print(f"Connecting to config server, attempt {attempt + 1} failed with ConnectionError: {e}")
                time.sleep(1)
            else:
                raise RuntimeError(f"Config server unreachable")
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to get config from config server: {e}")
        proxies = {"http": AuxiliaryConfig.get_socks_url(), "https": AuxiliaryConfig.get_socks_url()}
        try:
            response = requests.get(AuxiliaryConfig.get_config_url(), proxies=proxies)
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Cannot connect to config server via SOCKS proxy: {e}")
        print("Connectivity check to config server passes")

    def __run_nitro_enclave(self):
        command = [
            "nitro-cli", "run-enclave",
            "--eif-path", "/opt/uid2operator/uid2operator.eif",
            "--memory", str(self.configs["enclave_memory_mb"]),
            "--cpu-count", str(self.configs["enclave_cpu_count"]),
            "--enclave-cid", "42",
            "--enclave-name", "uid2operator"
        ]
        if self.configs.get('debug_mode', False):
            print("Running in debug_mode")
            command += ["--debug-mode", "--attach-console"]
        self.run_command(command, seperate_process=True)

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        secret_manager_key = self.__get_secret_name_from_userdata()
        self._set_secret(secret_manager_key)
        print(f"Fetched configs from {secret_manager_key}")
        if not self.configs.get("skip_validations"):
            self.validate_configuration()
        self._setup_auxiliaries()
        self._validate_auxiliaries()
        self.__run_nitro_enclave()

    def cleanup(self) -> None:
        """Terminates the Nitro Enclave and auxiliary processes."""
        try:
            self.run_command(["nitro-cli", "terminate-enclave", "--all"])
            self.__kill_auxiliaries()
        except subprocess.SubprocessError as e:
            raise (f"Error during cleanup: {e}")

    def __kill_auxiliaries(self) -> None:
        """Kills all auxiliary processes spawned."""
        for process_name in ["vsockpx", "sockd", "flask"]:
            try:
                result = subprocess.run(["pgrep", "-f", process_name], stdout=subprocess.PIPE, text=True, check=False)
                if result.stdout.strip():
                    for pid in result.stdout.strip().split("\n"):
                        os.kill(int(pid), signal.SIGKILL)
                    print(f"Killed process '{process_name}'.")
                else:
                    print(f"No process named '{process_name}' found.")
            except Exception as e:
                print(f"Error killing process '{process_name}': {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage EC2-based confidential compute workflows.")
    parser.add_argument("-o", "--operation", choices=["stop", "start"], default="start", help="Operation to perform.")
    args = parser.parse_args()
    try:
        ec2 = EC2()
        if args.operation == "stop":
            ec2.cleanup()
        else:
            ec2.run_compute()
    except ConfidentialComputeStartupException as e:
        print("Failed starting up Confidential Compute. Please checks the logs for errors and retry \n", e)
    except Exception as e:
         print("Unexpected failure while starting up Confidential Compute. Please contact UID support team with this log \n ", e)
           