#!/usr/bin/env python3

import os
import shutil
from typing import Dict
import sys
import logging
import requests
import re
from google.cloud import secretmanager
from google.auth.exceptions import DefaultCredentialsError
from google.api_core.exceptions import PermissionDenied, NotFound
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfigurationMissingError, OperatorKeyNotFoundError, OperatorKeyPermissionError, ConfidentialComputeStartupError


class AuxiliaryConfig:
    GCP_METADATA: str = "169.254.169.254"
    GCP_HEADER: dict = {"Metadata-Flavor": "Google"}

    @classmethod
    def get_gcp_instance_id_url(cls) -> str:
        return f"http://{cls.GCP_METADATA}/computeMetadata/v1/instance/id"

    @classmethod
    def get_gcp_image_url(cls) -> str:
        return f"http://{cls.GCP_METADATA}/computeMetadata/v1/instance/image"
    
class GCP(ConfidentialCompute):

    def __init__(self):
        super().__init__()

    def _set_confidential_config(self, secret_identifier=None) -> None:
        
        keys_mapping = {
            "core_base_url": "CORE_BASE_URL",
            "optout_base_url": "OPTOUT_BASE_URL",
            "environment": "DEPLOYMENT_ENVIRONMENT",
            "skip_validations": "SKIP_VALIDATIONS",
            "debug_mode": "DEBUG_MODE",
        }
        self.configs = {
            key: (os.environ[env_var].lower() == "true" if key in ["skip_validations", "debug_mode"] else os.environ[env_var])
            for key, env_var in keys_mapping.items() if env_var in os.environ
        }

        if not os.getenv("API_TOKEN_SECRET_NAME"):
            raise ConfigurationMissingError(self.__class__.__name__, ["API_TOKEN_SECRET_NAME"])
        try:
            client = secretmanager.SecretManagerServiceClient()
            secret_version_name = f"{os.getenv("API_TOKEN_SECRET_NAME")}"
            response = client.access_secret_version(name=secret_version_name)
            secret_value = response.payload.data.decode("UTF-8")
        except (PermissionDenied, DefaultCredentialsError) as e:
            raise OperatorKeyPermissionError(self.__class__.__name__, str(e))
        except NotFound:
            raise OperatorKeyNotFoundError(self.__class__.__name__, f"Secret Manager {os.getenv("API_TOKEN_SECRET_NAME")}")
        self.configs["operator_key"] = secret_value
        instance_id, version = self.__get_gcp_instance_info()
        self.configs["uid_instance_id_prefix"] = self.get_uid_instance_id(identifier=instance_id, version=version)
    
    def __populate_operator_config(self, destination):
        target_config = f"/app/conf/{self.configs["environment"].lower()}-config.json"
        shutil.copy(target_config, destination)
        with open(destination, 'r') as file:
            config = file.read()
        config = config.replace("https://core.uidapi.com", self.configs.get("core_base_url"))
        config = config.replace("https://optout.uidapi.com", self.configs.get("optout_base_url"))
        config = config.replace("unknown", self.configs.get("uid_instance_id_prefix"))
        with open(destination, 'w') as file:
            file.write(config)

    def _setup_auxiliaries(self) -> None:
        """ No Auxiliariy service required for GCP Confidential compute. """
        pass

    def _validate_auxiliaries(self) -> None:
        """ No Auxiliariy service required for GCP Confidential compute. """
        pass

    def __get_gcp_instance_info(self) -> tuple[str, str]:
        """Fetches the GCP instance ID, and image version."""
        try:
            response = requests.get(AuxiliaryConfig.get_gcp_instance_id_url(), headers=AuxiliaryConfig.GCP_HEADER, timeout=2)
            response.raise_for_status()
            instance_id = response.text.strip()
            image_response = requests.get(AuxiliaryConfig.get_gcp_image_url(), headers=AuxiliaryConfig.GCP_HEADER, timeout=2)
            image_response.raise_for_status()
            image = image_response.text.strip()
            match = re.search(r":(\d+\.\d+\.\d+)", image)
            version = match.group(1) if match else "unknown"
            return instance_id, version
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch GCP instance info: {e}")

    def run_compute(self) -> None:
        self._set_confidential_config()
        logging.info("Fetched configs")
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
    except ConfidentialComputeStartupError as e:
        logging.error(f"Failed starting up Confidential Compute. Please checks the logs for errors and retry {e}")
    except Exception as e:
        logging.error(f"Unexpected failure while starting up Confidential Compute. Please contact UID support team with this log {e}")
           
