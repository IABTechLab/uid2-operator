#!/usr/bin/env python3

import json
import os
import time
from typing import Dict
import sys
import shutil
import requests
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import ConfidentialCompute, ConfidentialComputeConfig, MissingConfig, ConfidentialComputeStartupException 
from azure.identity import DefaultAzureCredential, CredentialUnavailableError
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

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
        if AzureEntryPoint.kv_name is None:
            raise MissingConfig(self.__class__.__name__, ["VAULT_NAME"])        
        if AzureEntryPoint.secret_name is None:
            raise MissingConfig(self.__class__.__name__, ["OPERATOR_KEY_SECRET_NAME"])        
        if AzureEntryPoint.env_name is None:
            raise MissingConfig(self.__class__.__name__, ["DEPLOYMENT_ENVIRONMENT"])        
        print("Env variables validation success")
        
    def __wait_for_sidecar():
        url = "http://169.254.169.254/ping"
        delay = 2
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
                    print("Sidecar failed to start")
                    break
                delay += 1
    
    def __set_environment(self):
        self.configs["environment"] = AzureEntryPoint.env_name

    def _set_secret(self, secret_identifier: str = None):
        try:
            credential = DefaultAzureCredential()
            kv_URL = f"https://{AzureEntryPoint.kv_name}.vault.azure.net"
            secret_client = SecretClient(vault_url=kv_URL, credential=credential)
            secret = secret_client.get_secret(AzureEntryPoint.secret_name)
            # print(f"Secret Value: {secret.value}")
            self.configs["api_token"] = secret.value

        except CredentialUnavailableError as auth_error:
            print(f"Read operator key, authentication error: {auth_error}")
            raise

        except ResourceNotFoundError as not_found_error:
            print(f"Read operator key, secret not found: {AzureEntryPoint.secret_name}. Error: {not_found_error}")
            raise

        except HttpResponseError as http_error:
            print(f"Read operator key, HTTP error occurred: {http_error}")
            raise

        except Exception as e:
            print(f"Read operator key, an unexpected error occurred: {e}")
            raise

    def __create_final_config(self):      
        TARGET_CONFIG = f"/app/conf/{AzureEntryPoint.env_name}-uid2-config.json"
        if not os.path.isfile(TARGET_CONFIG):
            print(f"Unrecognized config {TARGET_CONFIG}")
            sys.exit(1)

        FINAL_CONFIG = "/tmp/final-config.json"
        print(f"-- copying {TARGET_CONFIG} to {FINAL_CONFIG}")
        try:
            shutil.copy(TARGET_CONFIG, FINAL_CONFIG)
        except IOError as e:
            print(f"Failed to create {FINAL_CONFIG} with error: {e}")
            sys.exit(1)

        CORE_BASE_URL = os.getenv("CORE_BASE_URL")
        OPTOUT_BASE_URL = os.getenv("OPTOUT_BASE_URL")
        if CORE_BASE_URL and OPTOUT_BASE_URL and AzureEntryPoint.env_name != 'prod':
            print(f"-- replacing URLs by {CORE_BASE_URL} and {OPTOUT_BASE_URL}")
            with open(FINAL_CONFIG, "r") as file:
                config = file.read()

            config = config.replace("https://core-integ.uidapi.com", CORE_BASE_URL)
            config = config.replace("https://optout-integ.uidapi.com", OPTOUT_BASE_URL)

            with open(FINAL_CONFIG, "w") as file:
                file.write(config)

        with open(FINAL_CONFIG, "r") as file:
            print(file.read())
    
    def __set_baseurls(self):
        final_config="/tmp/final-config.json"
        with open(final_config, "r") as file:
            jdata = json.load(file)
            self.configs["core_base_url"] = jdata["core_attest_url"]
            self.configs["optout_base_url"] = jdata["optout_api_uri"]

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
            f"-jar {AzureEntryPoint.jar_name}-{AzureEntryPoint.jar_version}.jar"
        ]
        print("-- starting java operator application")
        self.run_command(java_command, seperate_process=False)

    def __wait_for_sidecar(self):
        url = "http://169.254.169.254/ping"
        delay = 1
        max_retries = 15

        while True:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print("Sidecar started")
                    return
            except requests.RequestException:
                print(f"Sidecar not started. Retrying in {delay} seconds...")
                time.sleep(delay)
                if delay > max_retries:
                    print("Sidecar failed to start")
                    break
                delay += 1

    def run_compute(self) -> None:
        """Main execution flow for confidential compute."""
        self.__check_env_variables()
        self._set_secret()
        self.__set_environment()
        self.__create_final_config()
        self.__set_baseurls()
        if not self.configs.get("skip_validations"):
            self.validate_configuration()
        
        self.__wait_for_sidecar()
        self.__run_operator()

    def _setup_auxiliaries(self) -> None:
        """ Sets up auxiliary processes required for confidential computing. """
        pass

    def _validate_auxiliaries(self) -> None:
        """ Validates auxiliary services are running."""
        pass

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Test python logger")

    print("Start AzureEntryPoint")
    try:
        operator = AzureEntryPoint()
        operator.run_compute()

    except ConfidentialComputeStartupException as e:
        print("Failed starting up Azure Confidential Compute. Please checks the logs for errors and retry \n", e)
    except Exception as e:
         print("Unexpected failure while starting up Azure Confidential Compute. Please contact UID support team with this log \n ", e)          