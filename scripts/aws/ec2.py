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
from botocore.exceptions import ClientError
from typing import Dict
import sys
import time
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, ConfidentialComputeMissingConfigError

class EC2(ConfidentialCompute):

    def __init__(self):
        super().__init__()

    def __get_aws_token(self) -> str:
        """Fetches a temporary AWS EC2 metadata token."""
        try:
            token_url = "http://169.254.169.254/latest/api/token"
            response = requests.put(
                token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "3600"}, timeout=2
            )
            return response.text
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch aws token: {e}")

    def __get_current_region(self) -> str:
        """Fetches the current AWS region from EC2 instance metadata."""
        token = self.__get_aws_token()
        metadata_url = "http://169.254.169.254/latest/dynamic/instance-identity/document"
        headers = {"X-aws-ec2-metadata-token": token}
        try:
            response = requests.get(metadata_url, headers=headers, timeout=2)
            response.raise_for_status()
            return response.json()["region"]
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch region: {e}")
        
    def __validate_configs(self, secret):
        required_keys = ["operator_key", "environment", "core_base_url", "optout_base_url"]
        missing_keys = [key for key in required_keys if key not in secret]
        if missing_keys:
            raise ConfidentialComputeMissingConfigError(missing_keys)
        
        
    def _get_secret(self, secret_identifier: str) -> ConfidentialComputeConfig:
        secret_identifier = "uid2-config-stack-tjm-unvalidate-eif-test1"
        """Fetches a secret value from AWS Secrets Manager."""
        region = self.__get_current_region()
        client = boto3.client("secretsmanager", region_name=region)
        try:
            secret = json.loads(client.get_secret_value(SecretId=secret_identifier)["SecretString"])
            self.__validate_configs(secret)
            return self.__add_defaults(secret)
        except ClientError as e:
            raise RuntimeError(f"Unable to access Secrets Manager {secret_identifier}: {e}")

    @staticmethod
    def __add_defaults(configs: Dict[str, any]) -> ConfidentialComputeConfig:
        """Adds default values to configuration if missing."""
        try:
            with open("/etc/nitro_enclaves/allocator.yaml", "r") as file:
                nitro_config = yaml.safe_load(file)
            configs.setdefault("enclave_memory_mb", nitro_config['memory_mib'])
            configs.setdefault("enclave_cpu_count", nitro_config['cpu_count'])
        except Exception as e:
            raise RuntimeError("/etc/nitro_enclaves/allocator.yaml does not exist/ does not have cpu, memory allocated")
        configs.setdefault("debug_mode", False)
        #urls are currently not set anywhere and is overridden based on identity scope available only inside docker. Change to passing those through config values.
        #And these should be validated
        configs.setdefault("core_base_url", "https://core.uidapi.com" if configs["environment"] == "prod" else "https://core-integ.uidapi.com")
        configs.setdefault("optout_base_url", "https://optout.uidapi.com" if configs["environment"] == "prod" else "https://optout-integ.uidapi.com")
        return configs

    def __setup_vsockproxy(self, log_level: int) -> None:
        """
        Sets up the vsock proxy service.
        TODO: Evaluate adding vsock logging based on log_level here
        """
        thread_count = (multiprocessing.cpu_count() + 1) // 2
        command = [
            "/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml",
            "--workers", str(thread_count), "--log-level", str(log_level), "--daemon"
        ]
        subprocess.run(command)

    def __run_config_server(self,log_level = None) -> None:
        """
        Starts the Flask configuration server.
        TODO: Based on log level add logging to flask
        """
        os.makedirs("/etc/secret/secret-value", exist_ok=True)
        config_path = "/etc/secret/secret-value/config"
        with open(config_path, 'w') as config_file:
            json.dump(self.configs, config_file)
        os.chdir("/opt/uid2operator/config-server")
        command = ["./bin/flask", "run", "--host", "127.0.0.1", "--port", "27015"]
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"Failed to start the Flask config server.\n '{' '.join(command)}': {e}")
            raise RuntimeError ("Failed to start required flask server")

    def __run_socks_proxy(self, log_level = None) -> None:
        """
        Starts the SOCKS proxy service.
        TODO: Based on log level add logging to sockd
        """
        command = ["sockd", "-D"]
        subprocess.run(command)

    def __get_secret_name_from_userdata(self) -> str:
        """Extracts the secret name from EC2 user data."""
        token = self.__get_aws_token()
        user_data_url = "http://169.254.169.254/latest/user-data"
        response = requests.get(user_data_url, headers={"X-aws-ec2-metadata-token": token})
        user_data = response.text

        with open("/opt/uid2operator/identity_scope.txt") as file:
            identity_scope = file.read().strip()

        default_name = f"{identity_scope.lower()}-operator-config-key"
        hardcoded_value = f"{identity_scope.upper()}_CONFIG_SECRET_KEY"
        match = re.search(rf'^export {hardcoded_value}="(.+?)"$', user_data, re.MULTILINE)
        return match.group(1) if match else default_name

    def _setup_auxiliaries(self) -> None:
        """Sets up the necessary auxiliary services and configuration."""
        self.configs = self._get_secret(self.__get_secret_name_from_userdata())
        log_level = 3 if self.configs["debug_mode"] else 1
        self.__setup_vsockproxy(log_level)
        self.__run_config_server(log_level)
        self.__run_socks_proxy(log_level)
        time.sleep(5)  #TODO: Change to while loop if required. 

    def _validate_auxiliaries(self) -> None:
        """Validates auxiliary services."""
        self.validate_operator_key()
        proxy = "socks5://127.0.0.1:3306"
        config_url = "http://127.0.0.1:27015/getConfig"
        try:
            response = requests.get(config_url)
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Config server unreachable: {e}")
        proxies = {"http": proxy, "https": proxy}
        try:
            response = requests.get(config_url, proxies=proxies)
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Cannot connect to config server via SOCKS proxy: {e}")

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        self._setup_auxiliaries()
        self._validate_auxiliaries()
        self.validate_connectivity()
        command = [
            "nitro-cli", "run-enclave",
            "--eif-path", "/opt/uid2operator/uid2operator.eif",
            "--memory", str(self.configs["enclave_memory_mb"]),
            "--cpu-count", str(self.configs["enclave_cpu_count"]),
            "--enclave-cid", "42",
            "--enclave-name", "uid2operator"
        ]
        if self.configs["debug_mode"]:
            command += ["--debug-mode", "--attach-console"]
        subprocess.run(command, check=True)

    def cleanup(self) -> None:
        """Terminates the Nitro Enclave and auxiliary processes."""
        try:
            describe_output = subprocess.check_output(["nitro-cli", "describe-enclaves"], text=True)
            enclaves = json.loads(describe_output)
            enclave_id = enclaves[0].get("EnclaveID") if enclaves else None
            if enclave_id:
                subprocess.run(["nitro-cli", "terminate-enclave", "--enclave-id", enclave_id])
                print(f"Terminated enclave with ID: {enclave_id}")
            else:
                print("No active enclaves found.")
            self.__kill_auxiliaries()
        except subprocess.SubprocessError as e:
            raise (f"Error during cleanup: {e}")

    def __kill_auxiliaries(self) -> None:
        """Kills a process by its name."""
        try:
            for process_name in ["vsockpx", "sockd", "flask"]:
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
    ec2 = EC2()
    if args.operation == "stop":
        ec2.cleanup()
    else:
        ec2.run_compute()
           