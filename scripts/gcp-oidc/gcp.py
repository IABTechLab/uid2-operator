#!/usr/bin/env python3

import os
import shutil
from typing import Dict
import sys
from google.cloud import secretmanager
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.api_core.exceptions import PermissionDenied, NotFound

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, MissingConfig, ConfigNotFound, MissingInstanceProfile, ConfidentialComputeStartupException

class GCP(ConfidentialCompute):

    def __init__(self):
        super().__init__()

    def _get_secret(self, secret_identifier=None) -> ConfidentialComputeConfig:
        keys_mapping = {
            "core_base_url": "CORE_BASE_URL",
            "optout_base_url": "OPTOUT_BASE_URL",
            "environment": "DEPLOYMENT_ENVIRONMENT",
            "skip_validations": "SKIP_VALIDATIONS",
            "debug_mode": "DEBUG_MODE",
        }
        config: ConfidentialComputeConfig = {
            key: (os.environ[env_var].lower() == "true" if key in ["skip_validations", "debug_mode"] else os.environ[env_var])
            for key, env_var in keys_mapping.items() if env_var in os.environ
        }

        if not os.getenv("API_TOKEN_SECRET_NAME"):
            raise MissingConfig(self.__class__.__name__, ["API_TOKEN_SECRET_NAME"])
        try:
            client = secretmanager.SecretManagerServiceClient()
            secret_version_name = f"{os.getenv("API_TOKEN_SECRET_NAME")}/versions/latest"
            response = client.access_secret_version(name=secret_version_name)
            secret_value = response.payload.data.decode("UTF-8")
        except PermissionDenied or DefaultCredentialsError :
            raise MissingInstanceProfile(self.__class__.__name__)
        except NotFound:
            raise ConfigNotFound(self.__class__.__name__, f"Secret Manager {os.getenv("API_TOKEN_SECRET_NAME")}")
        config["api_token"] = secret_value
        return config
    
    def __populate_operator_config(self, destination):
        target_config = f"/app/conf/{self.configs["environment"].lower()}-config.json"
        shutil.copy(target_config, destination)
        with open(destination, 'r') as file:
            config = file.read()
        config = config.replace("https://core.uidapi.com", self.configs.get("core_base_url"))
        config = config.replace("https://optout.uidapi.com", self.configs.get("optout_base_url"))
        with open(destination, 'w') as file:
            file.write(config)

    def _setup_auxiliaries(self) -> None:
        """ No Auxiliariy service required for GCP Confidential compute. """
        pass

    def _validate_auxiliaries(self) -> None:
        """ No Auxiliariy service required for GCP Confidential compute. """
        pass

    def run_compute(self) -> None:
        self.configs = self._get_secret('read_from_env_vars')
        print(f"Fetched configs")
        if not self.configs.get("skip_validations"):
            self.validate_configuration()
        config_locaton = "/tmp/final-config.json"
        self.__populate_operator_config(config_locaton)
        os.environ["gcp_secret_version_name"] = os.getenv("API_TOKEN_SECRET_NAME")
        java_command = [
            "java",
            "-XX:MaxRAMPercentage=95", 
            "-XX:-UseCompressedOops", 
            "-XX:+PrintFlagsFinal",
            "-Djava.security.egd=file:/dev/./urandom",
            "-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory",
            "-Dlogback.configurationFile=/app/conf/logback.xml",
            f"-Dvertx-config-path={config_locaton}",
            "-jar",
            f"{os.getenv("JAR_NAME")}-{os.getenv("JAR_VERSION")}.jar"
        ]
        self.run_command(java_command)

if __name__ == "__main__":
    try:
        gcp = GCP()
        gcp.run_compute()
    except ConfidentialComputeStartupException as e:
        print("Failed starting up Confidential Compute. Please checks the logs for errors and retry \n", e)
    except Exception as e:
         print("Unexpected failure while starting up Confidential Compute. Please contact UID support team with this log \n ", e)
           
