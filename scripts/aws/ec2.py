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
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, OperatorConfig


class EC2(ConfidentialCompute):

    def __init__(self):
        super().__init__()
        self.configs: OperatorConfig = {}

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

    def _get_secret(self, secret_identifier: str) -> Dict:
        """Fetches a secret value from AWS Secrets Manager."""
        region = self.__get_current_region()
        client = boto3.client("secretsmanager", region_name=region)
        try:
            secret = client.get_secret_value(SecretId=secret_identifier)
            return json.loads(secret["SecretString"])
        except ClientError as e:
            raise RuntimeError(f"Unable to access Secrets Manager: {e}")

    @staticmethod
    def __add_defaults(configs: Dict[str, any]) -> OperatorConfig:
        """Adds default values to configuration if missing."""
        configs.setdefault("enclave_memory_mb", 24576)
        configs.setdefault("enclave_cpu_count", 6)
        configs.setdefault("debug_mode", False)
        configs.setdefault("core_base_url", "https://core.uidapi.com" if configs["environment"] == "prod" else "https://core-integ.uidapi.com")
        configs.setdefault("optout_base_url", "https://optout.uidapi.com" if configs["environment"] == "prod" else "https://optout-integ.uidapi.com")
        return configs

    @staticmethod
    def __error_out_on_execute(command: list, error_message: str) -> None:
        """Runs a command in the background and handles exceptions."""
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"{error_message} \n '{' '.join(command)}': {e}")

    def __setup_vsockproxy(self, log_level: int) -> None:
        """Sets up the vsock proxy service."""
        thread_count = (multiprocessing.cpu_count() + 1) // 2
        command = [
            "/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml",
            "--workers", str(thread_count), "--log-level", str(log_level), "--daemon"
        ]
        self.__error_out_on_execute(command, "vsockpx not found. Ensure it is installed.")

    def __run_config_server(self) -> None:
        """Starts the Flask configuration server."""
        os.makedirs("/etc/secret/secret-value", exist_ok=True)
        config_path = "/etc/secret/secret-value/config"
        with open(config_path, 'w') as config_file:
            json.dump(self.configs, config_file)
        os.chdir("/opt/uid2operator/config-server")
        command = ["./bin/flask", "run", "--host", "127.0.0.1", "--port", "27015"]
        self.__error_out_on_execute(command, "Failed to start the Flask config server.")

    def __run_socks_proxy(self) -> None:
        """Starts the SOCKS proxy service."""
        command = ["sockd", "-d"]
        self.__error_out_on_execute(command, "Failed to start socks proxy.")

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
        """Sets up the necessary auxiliary services and configurations."""
        hostname = os.getenv("HOSTNAME", default=os.uname()[1])
        try:
            with open("HOSTNAME", "w") as file:
                file.write(hostname)
            print(f"Hostname '{hostname}' written to file.")
        except Exception as e:
            """
            Ignoring error here, as we are currently not using this information anywhere. 
            But can be added in future for tracibility on debug
            """
            print(f"Error writing hostname: {e}")

        config = self._get_secret(self.__get_secret_name_from_userdata())
        self.configs = self.__add_defaults(config)
        log_level = 3 if self.configs["debug_mode"] else 1
        self.__setup_vsockproxy(log_level)
        self.__run_config_server()
        self.__run_socks_proxy()

    def _validate_auxiliaries(self) -> None:
        """Validates auxiliary services."""
        proxy = "socks5h://127.0.0.1:3305"
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
        self.validate_connectivity(self.configs)
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
        except subprocess.SubprocessError as e:
            raise (f"Error during cleanup: {e}")

    def kill_process(self, process_name: str) -> None:
        """Kills a process by its name."""
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
    ec2 = EC2()
    if args.operation == "stop":
        ec2.cleanup()
        for process in ["vsockpx", "sockd", "vsock-proxy"]:
            ec2.kill_process(process)
    else:
        ec2.run_compute()
           