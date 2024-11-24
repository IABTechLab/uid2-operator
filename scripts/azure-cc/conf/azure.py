import os
import subprocess
import time
import json
import sys
import requests
import re
from typing import Dict
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, OperatorConfig
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

class AzureCC(ConfidentialCompute):

    def __init__(self):
        super().__init__()
        self.configs: ConfidentialComputeConfig = {}
        
    def _get_secret(self, secret_identifier) -> ConfidentialComputeConfig:
        """Fetches a secret value from Azure Key Value, reads environment variables and returns config"""
        key_vault_url = "https://{}.vault.azure.net/".format(secret_identifier["key_vault"])
        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
        try:
          config = {
             "api_key" : secret_client.get_secret(secret_identifier["secret_name"]),
             "environment": os.getenv("DEPLOYMENT_ENVIRONMENT"),
             "core_base_url": os.getenv("CORE_BASE_URL"),
             "optout_base_url": os.getenv("OPTOUT_BASE_URL")
          }
          return self.__add_defaults({key: value for key, value in config.items() if value is not None})
        except Exception as e:
           raise RuntimeError(f"Unable to access Secrets Manager: {e}")

    def _setup_auxiliaries(self, secrets):
       """Sets up auxiliary configurations (placeholder for extension)."""
       pass

    def __validate_sidecar(self):
        """Validates the required sidecar is running"""
        url = "http://169.254.169.254/ping"
        delay = 1
        max_retries = 15
        while True:
          try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print("Sidecar started")
                break
          except requests.RequestException:
            print(f"Sidecar not started. Retrying in {delay} seconds...")
            time.sleep(delay)
            if delay > max_retries:
                raise RuntimeError("Unable to start operator as sidecar failed to start")
            delay += 1
        
  
    def _validate_auxiliaries(self, secrets):
        """Validates the presence of required environment variables, and sidecar is up"""
        self.__validate_sidecar()
        config_env_vars = [
          "VAULT_NAME",
          "OPERATOR_KEY_SECRET_NAME",
          "DEPLOYMENT_ENVIRONMENT"
        ]
        pre_set_env_vars = [
          "JAR_NAME",
          "JAR_VERSION" 
        ]
        for variable in (config_env_vars + pre_set_env_vars):
          value = os.getenv(variable)
          if not value:
              raise ValueError("{} is not set. Please update it".format(variable))
        if os.getenv("DEPLOYMENT_ENVIRONMENT") not in ["prod","integ"]:
          raise ValueError("DEPLOYMENT_ENVIRONMENT should be prod/integ. It is currently set to {}".format(os.getenv("DEPLOYMENT_ENVIRONMENT")))
        
    @staticmethod
    def __add_defaults(configs: Dict[str, any]) -> ConfidentialComputeConfig:
        """Adds default values to configuration if missing."""
        configs.setdefault("enclave_memory_mb", -1)
        configs.setdefault("enclave_cpu_count", -1)
        configs.setdefault("debug_mode", False)
        configs.setdefault("core_base_url", "https://core.uidapi.com" if configs["environment"] == "prod" else "https://core-integ.uidapi.com")
        configs.setdefault("optout_base_url", "https://optout.uidapi.com" if configs["environment"] == "prod" else "https://optout-integ.uidapi.com")
        return configs
    
    #TODO: This is repeated in GCP, EC2
    def __get_overriden_configs(self, config_path) -> OperatorConfig:
        """Returns the required configurations for operator. Only overrides if environment is integ"""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(config_path) as f:
           config_data = json.load(f)
        if all([os.getenv("CORE_BASE_URL"), os.getenv("OPTOUT_BASE_URL")]) and self.configs["environment"] != "prod":
            config_data = re.sub(r"https://core-integ\.uidapi\.com", os.getenv("CORE_BASE_URL"), config_data)
            config_data = re.sub(r"https://optout-integ\.uidapi\.com", os.getenv("OPTOUT_BASE_URL"), config_data)
        return config_data

    def run_compute(self):
        """Main execution flow for confidential compute."""
        self._setup_auxiliaries(None)
        self._validate_auxiliaries(None)
        secret_identifier = {
           "key_vault": os.getenv("OPERATOR_KEY_SECRET_NAME"),
           "secret_name": os.getenv("VAULT_NAME")
        }
        self.configs = self._get_secret(secret_identifier)
        self.validate_operator_key(self.configs)
        self.validate_connectivity(self.configs)
        os.environ["azure_vault_name"] = os.getenv("VAULT_NAME")
        os.environ["azure_secret_name"] = os.getenv("OPERATOR_KEY_SECRET_NAME")
        config_path="/app/conf/${}-uid2-config.json".format(os.getenv("DEPLOYMENT_ENVIRONMENT"))
        with open(config_path, "w") as file:
            file.write(self.__get_overriden_configs(config_path=config_path))
        java_command = [
          "java",
          "-XX:MaxRAMPercentage=95",
          "-XX:-UseCompressedOops",
          "-XX:+PrintFlagsFinal",
          "-Djava.security.egd=file:/dev/./urandom",
          "-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory",
          "-Dlogback.configurationFile=/app/conf/logback.xml",
          "-Dvertx-config-path={}".format(config_path),
          "-jar",
          "{}-{}.jar".format(os.getenv("JAR_NAME"), os.getenv("JAR_VERSION"))
        ]
        try:
          subprocess.run(java_command, check=True)
        except subprocess.CalledProcessError as e:
          print(f"Error starting the Java application: {e}")


if __name__ == "__main__":
    AzureCC().run_compute()