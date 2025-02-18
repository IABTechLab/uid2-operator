#!/usr/bin/env python3

import json
import os
import time
from typing import Dict
import sys
import shutil
import requests
import logging
from confidential_compute import ConfidentialCompute, ConfigurationMissingError, OperatorKeyPermissionError, OperatorKeyNotFoundError, ConfidentialComputeStartupError
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, CredentialUnavailableError
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AzureEntryPoint(ConfidentialCompute):
  
    kv_name = os.getenv("VAULT_NAME")
    secret_name = os.getenv("OPERATOR_KEY_SECRET_NAME")
    env_name = os.getenv("DEPLOYMENT_ENVIRONMENT")
    jar_name = os.getenv("JAR_NAME", "default-jar-name")
    jar_version = os.getenv("JAR_VERSION", "default-jar-version")

    FINAL_CONFIG = "/tmp/final-config.json"

    def __init__(self):
        super().__init__()

    def __check_env_variables(self):
        # Check essential env variables
        if AzureEntryPoint.kv_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["VAULT_NAME"])        
        if AzureEntryPoint.secret_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["OPERATOR_KEY_SECRET_NAME"])        
        if AzureEntryPoint.env_name is None:
            raise ConfigurationMissingError(self.__class__.__name__, ["DEPLOYMENT_ENVIRONMENT"])        
        logging.info("Environment variables validation success")

    def __create_final_config(self):      
        TARGET_CONFIG = f"/app/conf/{AzureEntryPoint.env_name}-uid2-config.json"
        if not os.path.isfile(TARGET_CONFIG):
            logging.error(f"Unrecognized config {TARGET_CONFIG}")
            sys.exit(1)

        logging.info(f"-- copying {TARGET_CONFIG} to {AzureEntryPoint.FINAL_CONFIG}")
        try:
            shutil.copy(TARGET_CONFIG, AzureEntryPoint.FINAL_CONFIG)
        except IOError as e:
            logging.error(f"Failed to create {AzureEntryPoint.FINAL_CONFIG} with error: {e}")
            sys.exit(1)
        
        if self.configs["core_base_url"] and self.configs["optout_base_url"] and AzureEntryPoint.env_name != 'prod':
            logging.info(f"-- replacing URLs by {self.configs["core_base_url"]} and {self.configs["optout_base_url"]}")
            with open(AzureEntryPoint.FINAL_CONFIG, "r") as file:
                config = file.read()

            config = config.replace("https://core-integ.uidapi.com", self.configs["core_base_url"])
            config = config.replace("https://optout-integ.uidapi.com", self.configs["optout_base_url"])

            with open(AzureEntryPoint.FINAL_CONFIG, "w") as file:
                file.write(config)

        with open(AzureEntryPoint.FINAL_CONFIG, "r") as file:
            logging.info(file.read())

    def __set_base_urls(self):
        with open(AzureEntryPoint.FINAL_CONFIG, "r") as file:
            jdata = json.load(file)
            self.configs["core_base_url"] = jdata["core_attest_url"]
            self.configs["optout_base_url"] = jdata["optout_api_uri"]

    def __set_operator_key(self):
        try:
            credential = DefaultAzureCredential()
            kv_URL = f"https://{AzureEntryPoint.kv_name}.vault.azure.net"
            secret_client = SecretClient(vault_url=kv_URL, credential=credential)
            secret = secret_client.get_secret(AzureEntryPoint.secret_name)
            # print(f"Secret Value: {secret.value}")
            self.configs["operator_key"] = secret.value

        except (CredentialUnavailableError, ClientAuthenticationError) as auth_error:
            logging.error(f"Read operator key, authentication error: {auth_error}")
            raise OperatorKeyPermissionError(self.__class__.__name__, str(auth_error))
        except ResourceNotFoundError as not_found_error:
            logging.error(f"Read operator key, secret not found: {AzureEntryPoint.secret_name}. Error: {not_found_error}")
            raise OperatorKeyNotFoundError(self.__class__.__name__, str(not_found_error))
        

    def _set_confidential_config(self, secret_identifier: str = None):
        self.configs["skip_validations"] = os.getenv("SKIP_VALIDATIONS", "true").lower() == "true"
        self.configs["debug_mode"] = os.getenv("DEBUG_MODE", "true").lower() == "true"
        self.configs["environment"] = AzureEntryPoint.env_name

        # set self.configs["operator_key"]
        self.__set_operator_key()
        # set base urls from final config file
        self.__set_base_urls()

    def __run_operator(self):

        # Start the operator
        os.environ["azure_vault_name"] = AzureEntryPoint.kv_name
        os.environ["azure_secret_name"] = AzureEntryPoint.secret_name

        java_command = [
            "java",
            "-XX:MaxRAMPercentage=95", "-XX:-UseCompressedOops", "-XX:+PrintFlagsFinal",
            "-Djava.security.egd=file:/dev/./urandom",
            "-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory",
            "-Dlogback.configurationFile=/app/conf/logback.xml",
            f"-Dvertx-config-path={AzureEntryPoint.FINAL_CONFIG}",
            "-jar", 
            f"{AzureEntryPoint.jar_name}-{AzureEntryPoint.jar_version}.jar"
        ]
        logging.info("-- starting java operator application")
        self.run_command(java_command, separate_process=False)

    def _validate_auxiliaries(self):
        logging.info("Waiting for sidecar ...")

        MAX_RETRIES = 15
        PING_URL = "http://169.254.169.254/ping"
        delay = 1

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = requests.get(PING_URL, timeout=5)
                if response.status_code in [200, 204]:
                    logging.info("Sidecar started successfully.")
                    return
                else:
                    logging.warning(
                        f"Attempt {attempt}: Unexpected status code {response.status_code}. Response: {response.text}"
                    )
            except Exception as e:
                logging.info(f"Attempt {attempt}: Error during request - {e}")

            if attempt == MAX_RETRIES:
                raise RuntimeError(f"Unable to detect sidecar running after {MAX_RETRIES} attempts. Exiting.")

            logging.info(f"Retrying in {delay} seconds... (Attempt {attempt}/{MAX_RETRIES})")
            time.sleep(delay)
            delay += 1

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        self.__check_env_variables()
        self.__create_final_config()
        self._set_confidential_config()
        if not self.configs.get("skip_validations"):
            self.validate_configuration()
        self._setup_auxiliaries()
        self.__run_operator()

    def _setup_auxiliaries(self) -> None:
        """ setup auxiliary services are running."""
        pass

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    logging.info("Start AzureEntryPoint")
    try:
        operator = AzureEntryPoint()
        operator.run_compute()
    except ConfidentialComputeStartupError as e:
        logging.error(f"Failed starting up Azure Confidential Compute. Please checks the logs for errors and retry {e}", exc_info=True)
    except Exception as e:
        logging.error(f"Unexpected failure while starting up Azure Confidential Compute. Please contact UID support team with this log {e}", exc_info=True)          