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
import logging
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List
import sys
import time
import yaml
logging.basicConfig(level=logging.INFO)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, InstanceProfileMissingError, OperatorKeyNotFoundError, ConfigurationValueError, ConfidentialComputeStartupError

class AWSConfidentialComputeConfig(ConfidentialComputeConfig):
    enclave_memory_mb: int
    enclave_cpu_count: int
    core_api_token: str
    optout_api_token: str

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
        super().__init__()

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
        
    def __get_ec2_instance_info(self) -> tuple[str, str]:
        """Fetches the instance ID, and AMI ID from EC2 metadata."""
        token = self.__get_aws_token()
        headers = {"X-aws-ec2-metadata-token": token}
        try:
            response = requests.get(AuxiliaryConfig.get_meta_url(), headers=headers, timeout=2)
            response.raise_for_status()
            data = response.json()
            instance_id = data["instanceId"]
            ami_id = data["imageId"]
            return instance_id, ami_id

        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch instance info: {e}")
        
    def __validate_aws_specific_config(self):
        if "enclave_memory_mb" in self.configs or "enclave_cpu_count" in self.configs:
            max_capacity = self.__get_max_capacity()
            if self.configs.get('enclave_memory_mb') < 11000 or self.configs.get('enclave_memory_mb') > max_capacity.get('enclave_memory_mb'):
                raise ConfigurationValueError(self.__class__.__name__, f"enclave_memory_mb must be in range 11000 and {max_capacity.get('enclave_memory_mb')}")
            if self.configs.get('enclave_cpu_count') < 2 or self.configs.get('enclave_cpu_count') > max_capacity.get('enclave_cpu_count'):
                raise ConfigurationValueError(self.__class__.__name__, f"enclave_cpu_count must be in range 2 and {max_capacity.get('enclave_cpu_count')}")
        
    def _set_confidential_config(self, secret_identifier: str) -> None:
        """Fetches a secret value from AWS Secrets Manager and adds defaults"""

        def add_defaults(configs: Dict[str, any]) ->  AWSConfidentialComputeConfig:
            """Adds default values to configuration if missing. Sets operator_key if only api_token is specified for backward compatibility """
            default_capacity = self.__get_max_capacity()
            configs.setdefault("operator_key", configs.get("api_token"))
            configs.setdefault("enclave_memory_mb", default_capacity["enclave_memory_mb"])
            configs.setdefault("enclave_cpu_count", default_capacity["enclave_cpu_count"])
            configs.setdefault("debug_mode", False)
            configs.setdefault("core_api_token", configs.get("operator_key"))
            configs.setdefault("optout_api_token", configs.get("operator_key"))
            return configs
        
        region = self.__get_current_region()
        logging.info(f"Running in {region}")
        client = boto3.client("secretsmanager", region_name=region)
        try:
            self.configs = add_defaults(json.loads(client.get_secret_value(SecretId=secret_identifier)["SecretString"]))
            instance_id, ami_id = self.__get_ec2_instance_info()
            self.configs.setdefault("uid_instance_id_prefix", self.get_uid_instance_id(identifier=instance_id,version=ami_id))
            self.__validate_aws_specific_config()
        except json.JSONDecodeError as e:
            raise OperatorKeyNotFoundError(self.__class__.__name__, f"Can not parse secret {secret_identifier} in {region}")
        except NoCredentialsError as _:
            raise InstanceProfileMissingError(self.__class__.__name__)
        except ClientError as _:
            raise OperatorKeyNotFoundError(self.__class__.__name__, f"Secret Manager {secret_identifier} in {region}")
        
    @staticmethod
    def __get_max_capacity():
        try:
            with open("/etc/nitro_enclaves/allocator.yaml", "r") as file:
                nitro_config = yaml.safe_load(file)
            return {"enclave_memory_mb": nitro_config['memory_mib'],  "enclave_cpu_count": nitro_config['cpu_count']}
        except Exception as e:
            raise RuntimeError("/etc/nitro_enclaves/allocator.yaml does not have CPU, memory allocated")

    def __setup_vsockproxy(self) -> None:
        logging.info("Sets up the vSock proxy service")
        thread_count = (multiprocessing.cpu_count() + 1) // 2
        command = [
            "/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml",
            "--workers", str(thread_count), "--daemon"
        ]

        debug_command = [
            "/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml",
            "--workers", str(thread_count), "--log-level", "0"
        ]

        self.run_service([command, debug_command], "vsock_proxy")

    def __run_config_server(self) -> None:
        logging.info("Starts the Flask configuration server")
        os.makedirs("/etc/secret/secret-value", exist_ok=True)
        config_path = "/etc/secret/secret-value/config"

        # Save configs to a file
        with open(config_path, 'w') as config_file:
            json.dump(self.configs, config_file)

        os.chdir("/opt/uid2operator/config-server")
        command = ["./bin/flask", "run", "--host", AuxiliaryConfig.LOCALHOST, "--port", AuxiliaryConfig.FLASK_PORT]

        self.run_service([command, command], "flask_config_server", separate_process=True)

    def __fix_network_interface_in_sockd_conf(self) -> None:
        """
        Auto-detects the primary network interface and updates /etc/sockd.conf.
        This fixes compatibility with R7i instances which use 'enp39s0' instead of 'ens5'.
        """
        logging.info("Auto-detecting network interface for SOCKS proxy configuration")
        
        try:
            result = subprocess.run(
                ["ip", "-o", "route", "get", "1"],
                capture_output=True, text=True, check=True
            )
            match = re.search(r'dev\s+(\S+)', result.stdout)
            primary_interface = match.group(1) if match else "ens5"
            
            logging.info(f"Detected primary network interface: {primary_interface}")
            
            with open('/etc/sockd.conf', 'r') as f:
                config = f.read()
            
            new_config = re.sub(r'external:\s+\w+', f'external: {primary_interface}', config)
            
            with open('/etc/sockd.conf', 'w') as f:
                f.write(new_config)
            
            logging.info(f"Updated /etc/sockd.conf with interface: {primary_interface}")
            
        except Exception as e:
            logging.error(f"Failed to auto-detect network interface: {e}")
            logging.info("Continuing with existing /etc/sockd.conf configuration")

    def __run_socks_proxy(self) -> None:
        logging.info("Starts the SOCKS proxy service")
        
        self.__fix_network_interface_in_sockd_conf()
        
        command = ["sockd", "-D"]

        # -d specifies debug level
        debug_command = ["sockd", "-d", "0"]

        self.run_service([command, debug_command], "socks_proxy")

    def run_service(self, command: List[List[str]], log_filename: str, separate_process: bool = False) -> None:
        """
        Runs a service command with logging if debug_mode is enabled.

        :param command: command[0] regular command, command[1] debug mode command
        :param log_filename: Base name of the log file (e.g., "flask_config_server", "socks_proxy", "vsock_proxy")
        :param separate_process: Whether to run in a separate process
        """
        log_file = f"/var/log/{log_filename}.log"

        if self.configs.get("debug_mode") is True:
            
            # Remove old log file to start fresh
            if os.path.exists(log_file):
                os.remove(log_file)

            # Set up logging
            logging.basicConfig(
                filename=log_file,
                filemode="w",
                level=logging.DEBUG,
                format="%(asctime)s %(levelname)s: %(message)s"
            )

            logging.info(f"Debug mode is on, logging into {log_file}")

            # Run debug mode command
            with open(log_file, "a") as log:
                self.run_command(command[1], separate_process=True, stdout=log, stderr=log)
        else:
            # Run regular command, possibly daemon
            self.run_command(command[0], separate_process=separate_process)

    def __get_secret_name_from_userdata(self) -> str:
        """Extracts the secret name from EC2 user data."""
        logging.info("Extracts the secret name from EC2 user data")
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
        self.__setup_vsockproxy()
        self.__run_config_server()
        self.__run_socks_proxy()
        logging.info("Finished setting up all auxiliaries")

    def _validate_auxiliaries(self) -> None:
        """Validates connection to flask server direct and through socks proxy."""
        logging.info("Validating auxiliaries")
        try:
            for attempt in range(10):
                try:
                    response = requests.get(AuxiliaryConfig.get_config_url())
                    logging.info("Config server is reachable")
                    break
                except requests.exceptions.ConnectionError as e:
                    logging.error(f"Connecting to config server, attempt {attempt + 1} failed with ConnectionError: {e}")
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
        logging.info("Connectivity check to config server passes")

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
            logging.info("Running nitro in debug_mode")
            command += ["--debug-mode", "--attach-console"]
        self.run_command(command, separate_process=False)

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        secret_manager_key = self.__get_secret_name_from_userdata()
        self._set_confidential_config(secret_manager_key)
        logging.info(f"Fetched configs from {secret_manager_key}")
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
                    logging.info(f"Killed process '{process_name}'.")
                else:
                    logging.info(f"No process named '{process_name}' found.")
            except Exception as e:
                logging.error(f"Error killing process '{process_name}': {e}")


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
    except ConfidentialComputeStartupError as e:
        logging.error(f"Failed starting up Confidential Compute. Please checks the logs for errors and retry {e}")
    except Exception as e:
        logging.error(f"Unexpected failure while starting up Confidential Compute. Please contact UID support team with this log {e}")
           
