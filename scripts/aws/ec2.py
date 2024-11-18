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
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute

class EC2(ConfidentialCompute):

    def __init__(self):
        super().__init__()
        self.config = {}

    def _get_secret(self, secret_identifier):
        client = boto3.client("secretsmanager", region_name=self.__get_current_region())
        try:
            secret = client.get_secret_value(SecretId=secret_identifier)
            return json.loads(secret["SecretString"])
        except ClientError as e:
            raise Exception("Unable to access secret store")
        
    def __add_defaults(self, configs):
        configs.setdefault("enclave_memory_mb", 24576)
        configs.setdefault("enclave_cpu_count", 6)
        configs.setdefault("debug_mode", False)
        return configs

    def __setup_vsockproxy(self, log_level):
        thread_count = int((multiprocessing.cpu_count() + 1) // 2)
        log_level = log_level
        try:
            subprocess.Popen(["/usr/bin/vsockpx", "-c", "/etc/uid2operator/proxy.yaml", "--workers", str(thread_count), "--log-level", log_level, "--daemon"])
            print("VSOCK proxy is now running in the background")
        except FileNotFoundError:
            print("Error: vsockpx not found. Please ensure the path is correct")
        except Exception as e:
            print("Failed to start VSOCK proxy")

    def __run_config_server(self, log_level):
        os.makedirs("/etc/secret/secret-value", exist_ok=True)
        with open('/etc/secret/secret-value/config', 'w') as fp:
            json.dump(self.configs, fp)
        os.chdir("/opt/uid2operator/config-server")
        # TODO: Add --log-level to flask. 
        try:
            subprocess.Popen(["./bin/flask", "run", "--host", "127.0.0.1", "--port", "27015"])
            print("Config server is now running in the background.")
        except Exception as e:
            print(f"Failed to start config server: {e}")

    def __run_socks_proxy(self, log_level):
        subprocess.Popen(["sockd", "-d"])

    def _validate_auxilaries(self):
        proxy = "socks5h://127.0.0.1:3305"
        url = "http://127.0.0.1:27015/getConfig"
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception("Config server unreachable")
        proxies = {
            "http": proxy,
            "https": proxy,
        }
        try:
            response = requests.get(url, proxies=proxies)
            response.raise_for_status() 
        except Exception as e:
            raise Exception(f"Cannot conect to config server through socks5: {e}")
        pass

    def __get_aws_token(self):
        try:
            token_url = "http://169.254.169.254/latest/api/token"
            token_response = requests.put(token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "3600"}, timeout=2)
            return token_response.text
        except Exception as e:
            return "blank"
    
    def __get_current_region(self):
        token = self.__get_aws_token()
        metadata_url = "http://169.254.169.254/latest/dynamic/instance-identity/document"
        headers = {"X-aws-ec2-metadata-token": token}
        try:
            response = requests.get(metadata_url, headers=headers,timeout=2)
            if response.status_code == 200:
                return response.json().get("region")
            else:
                print(f"Failed to fetch region, status code: {response.status_code}")  
        except Exception as e:
            raise Exception(f"Region not found, are you running in EC2 environment. {e}")

    def __get_secret_name_from_userdata(self):
        token = self.__get_aws_token()
        user_data_url = "http://169.254.169.254/latest/user-data"
        user_data_response = requests.get(user_data_url, headers={"X-aws-ec2-metadata-token": token})
        user_data = user_data_response.text
        identity_scope = open("/opt/uid2operator/identity_scope.txt").read().strip()
        default_name = "{}-operator-config-key".format(identity_scope.lower())
        hardcoded_value = "{}_CONFIG_SECRET_KEY".format(identity_scope.upper())
        match = re.search(rf'^export {hardcoded_value}="(.+?)"$', user_data, re.MULTILINE)
        return match.group(1) if match else default_name

    def _setup_auxilaries(self):
        hostname = os.getenv("HOSTNAME", default=os.uname()[1])
        file_path = "HOSTNAME"
        try:
            with open(file_path, "w") as file:
                file.write(hostname)
                print(f"Hostname '{hostname}' written to {file_path}")
        except Exception as e:
            print(f"An error occurred : {e}")
        config = self._get_secret(self.__get_secret_name_from_userdata())
        self.configs = self.__add_defaults(config)
        log_level = 3 if self.configs['debug_mode'] else 1
        self.__setup_vsockproxy(log_level)
        self.__run_config_server(log_level)
        self.__run_socks_proxy(log_level)

    def run_compute(self):
        self._setup_auxilaries()
        self._validate_auxilaries()
        command = [
            "nitro-cli", "run-enclave",
            "--eif-path", "/opt/uid2operator/uid2operator.eif",
            "--memory", self.config['enclave_memory_mb'],
            "--cpu-count", self.config['enclave_cpu_count'],
            "--enclave-cid", 42,
            "--enclave-name", "uid2operator"
        ]
        if self.config['debug']:
            command+=["--debug-mode", "--attach-console"]
        subprocess.run(command, check=True)

    def cleanup(self):
        describe_output = subprocess.check_output(["nitro-cli", "describe-enclaves"], text=True)
        enclaves = json.loads(describe_output)
        enclave_id = enclaves[0].get("EnclaveID") if enclaves else None
        if enclave_id:
            subprocess.run(["nitro-cli", "terminate-enclave", "--enclave-id", enclave_id])
            print(f"Enclave with ID {enclave_id} has been terminated.")
        else:
            print("No enclave found or EnclaveID is null.")

    def kill_process(self, process_name):
        try:
            result = subprocess.run(
                ["pgrep", "-f", process_name], 
                stdout=subprocess.PIPE, 
                text=True, 
                check=False
            )
            if result.stdout.strip():
                for pid in result.stdout.strip().split("\n"):
                    os.kill(int(pid), signal.SIGKILL)
                print(f"{process_name} exited")
            else:
                print(f"Process {process_name} not found")
        except Exception as e:
            print(f"Failed to shut down {process_name}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--operation", required=False)
    args = parser.parse_args()
    ec2 = EC2()
    if args.operation and args.operation == "stop":
        ec2.cleanup()
        [ec2.kill_process(process) for process in ["vsockpx", "sockd", "vsock-proxy", "nohup"]]
    else:
        ec2.run_compute()
