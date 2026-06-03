#!/usr/bin/env python3

import json
import os
import socket
import time
from typing import Dict
import sys
import shutil
import requests
import logging
from datetime import datetime
from confidential_compute import ConfidentialCompute, ConfigurationMissingError, OperatorKeyPermissionError, OperatorKeyNotFoundError, ConfidentialComputeStartupError
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, CredentialUnavailableError
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AZR(ConfidentialCompute):
    kv_name = os.getenv("VAULT_NAME")
    secret_name = os.getenv("OPERATOR_KEY_SECRET_NAME")
    env_name = os.getenv("DEPLOYMENT_ENVIRONMENT")
    jar_name = os.getenv("JAR_NAME", "default-jar-name")
    jar_version = os.getenv("JAR_VERSION", "default-jar-version")
    default_core_endpoint = f"https://core-{env_name}.uidapi.com".lower()
    default_optout_endpoint = f"https://optout-{env_name}.uidapi.com".lower()

    FINAL_CONFIG = "/tmp/final-config.json"
    SKR_HOST = "localhost"
    SKR_PORT = 9000

    def __init__(self):
        super().__init__()

    def __check_env_variables(self):
        # Check essential env variables
        if AZR.kv_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["VAULT_NAME"])        
        if AZR.secret_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["OPERATOR_KEY_SECRET_NAME"])        
        if AZR.env_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["DEPLOYMENT_ENVIRONMENT"])        
        logging.info("Environment variables validation success")

    def __create_final_config(self):      
        TARGET_CONFIG = f"/app/conf/{AZR.env_name}-uid2-config.json"
        if not os.path.isfile(TARGET_CONFIG):
            logging.error(f"Unrecognized config {TARGET_CONFIG}")
            sys.exit(1)

        logging.info(f"-- copying {TARGET_CONFIG} to {AZR.FINAL_CONFIG}")
        try:
            shutil.copy(TARGET_CONFIG, AZR.FINAL_CONFIG)
        except IOError as e:
            logging.error(f"Failed to create {AZR.FINAL_CONFIG} with error: {e}")
            sys.exit(1)
        
        logging.info(f"-- replacing URLs by {self.configs["core_base_url"]} and {self.configs["optout_base_url"]}")
        with open(AZR.FINAL_CONFIG, "r") as file:
            config = file.read()

        config = config.replace("https://core.uidapi.com", self.configs["core_base_url"])
        config = config.replace("https://optout.uidapi.com", self.configs["optout_base_url"])
        config = config.replace("unknown", self.configs["uid_instance_id_prefix"])
        with open(AZR.FINAL_CONFIG, "w") as file:
            file.write(config)

        with open(AZR.FINAL_CONFIG, "r") as file:
            logging.info(file.read())

    def __set_operator_key(self):
        try:
            credential = DefaultAzureCredential()
            kv_URL = f"https://{AZR.kv_name}.vault.azure.net"
            secret_client = SecretClient(vault_url=kv_URL, credential=credential)
            secret = secret_client.get_secret(AZR.secret_name)
            self.configs["operator_key"] = secret.value

        except (CredentialUnavailableError, ClientAuthenticationError) as auth_error:
            logging.error(f"Read operator key, authentication error: {auth_error}")
            raise OperatorKeyPermissionError(self.__class__.__name__, str(auth_error))
        except ResourceNotFoundError as not_found_error:
            logging.error(f"Read operator key, secret not found: {AZR.secret_name}. Error: {not_found_error}")
            raise OperatorKeyNotFoundError(self.__class__.__name__, str(not_found_error))
        
    def __get_azure_image_info(self) -> str:
        """
        Fetches Image version from non-modifiable environment variable.
        """
        try:
            return os.getenv("IMAGE_VERSION")
        except Exception as e:
            raise RuntimeError(f"Failed to fetch Azure image info: {e}")
        

    def _set_confidential_config(self, secret_identifier: str = None):
        """Builds and sets ConfidentialComputeConfig"""
        self.configs["skip_validations"] = os.getenv("SKIP_VALIDATIONS", "false").lower() == "true"
        self.configs["debug_mode"] = os.getenv("DEBUG_MODE", "false").lower() == "true"
        self.configs["environment"] = AZR.env_name
        self.configs["core_base_url"] = os.getenv("CORE_BASE_URL") if os.getenv("CORE_BASE_URL") and AZR.env_name == "integ" else AZR.default_core_endpoint
        self.configs["optout_base_url"] = os.getenv("OPTOUT_BASE_URL")  if os.getenv("OPTOUT_BASE_URL") and AZR.env_name == "integ" else AZR.default_optout_endpoint
        image_version = self.__get_azure_image_info()
        self.configs["uid_instance_id_prefix"] = self.get_uid_instance_id(identifier=datetime.now().strftime("%H:%M:%S"), version=image_version)
        self.__set_operator_key()

    def __run_operator(self):
        os.environ["azure_vault_name"] = AZR.kv_name
        os.environ["azure_secret_name"] = AZR.secret_name
        java_command = [
            "java",
            "-XX:MaxRAMPercentage=95", "-XX:-UseCompressedOops", "-XX:+PrintFlagsFinal",
            "-Djava.security.egd=file:/dev/./urandom",
            "-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory",
            "-Dlogback.configurationFile=/app/conf/logback.xml",
            f"-Dvertx-config-path={AZR.FINAL_CONFIG}",
            "-jar", 
            f"{AZR.jar_name}-{AZR.jar_version}.jar"
        ]
        logging.info("-- starting java operator application")
        self.run_command(java_command, separate_process=False)

    def _validate_auxiliaries(self):
        # Block JVM start until SKR is accepting TCP connections on :9000.
        # Without this, the first attestation calls race the sidecar's HTTP
        # server warmup and Core sees BAD_PAYLOAD (signature on a
        # half-bootstrapped MAA token).
        MAX_RETRIES = 15
        delay = 1

        logging.info(f"Waiting for SKR sidecar on {AZR.SKR_HOST}:{AZR.SKR_PORT} ...")

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with socket.create_connection((AZR.SKR_HOST, AZR.SKR_PORT), timeout=5):
                    logging.info("SKR sidecar is ready.")
                    return
            except OSError as e:
                logging.info(f"Attempt {attempt}: SKR sidecar not ready - {e}")

            if attempt == MAX_RETRIES:
                raise RuntimeError(f"SKR sidecar not ready after {MAX_RETRIES} attempts. Exiting.")

            logging.info(f"Retrying in {delay} seconds... (Attempt {attempt}/{MAX_RETRIES})")
            time.sleep(delay)
            delay += 1

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        self.__check_env_variables()
        self._set_confidential_config()
        if not self.configs.get("skip_validations"):
            self.validate_configuration()
        self.__create_final_config()
        self._setup_auxiliaries()
        self._validate_auxiliaries()
        self.__run_operator()

    def _setup_auxiliaries(self) -> None:
        # No-op for Azure CC: the SKR sidecar is a separate container declared
        # in the ARM template and started by Azure ACI alongside this one. We
        # only need to wait for it (see _validate_auxiliaries), not start it.
        pass

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    logging.info("Start Azure")
    try:
        operator = AZR()
        operator.run_compute()
    except ConfidentialComputeStartupError as e:
        logging.error(f"Failed starting up Azure Confidential Compute. Please checks the logs for errors and retry {e}", exc_info=True)
    except Exception as e:
        logging.error(f"Unexpected failure while starting up Azure Confidential Compute. Please contact UID support team with this log {e}", exc_info=True)          
