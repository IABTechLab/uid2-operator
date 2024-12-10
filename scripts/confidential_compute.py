import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict
import subprocess

class ConfidentialComputeConfig(TypedDict):
    enclave_memory_mb: int
    enclave_cpu_count: int
    debug_mode: bool
    api_token: str
    core_base_url: str
    optout_base_url: str
    environment: str
    
class ConfidentialCompute(ABC):

    def __init__(self):
        self.configs: ConfidentialComputeConfig = {}

    def validate_environment(self):
        def validate_url(url_key, environment):
            """URL should include environment except in prod"""
            if environment != "prod" and environment not in self.configs[url_key]:
                raise ValueError(
                    f"{url_key} must match the environment. Ensure the URL includes '{environment}'."
                )
            parsed_url = urlparse(self.configs[url_key])
            if parsed_url.scheme != 'https' and parsed_url.path:
                raise ValueError(
                    f"{url_key} is invalid. Ensure {self.configs[url_key]} follows HTTPS, and doesn't have any path specified."
                )
            
        environment = self.configs["environment"]

        if self.configs.get("debug_mode") and environment == "prod":
            raise ValueError("Debug mode cannot be enabled in the production environment.")
        
        validate_url("core_base_url", environment)
        validate_url("optout_base_url", environment)


    def validate_operator_key(self):
        """ Validates the operator key format and its environment alignment."""
        operator_key = self.configs.get("api_token")
        if not operator_key:
            raise ValueError("API token is missing from the configuration.")
        pattern = r"^(UID2|EUID)-.\-(I|P)-\d+-\*$"
        if re.match(pattern, operator_key):
            env = self.configs.get("environment", "").lower()
            debug_mode = self.configs.get("debug_mode", False)
            expected_env = "I" if debug_mode or env == "integ" else "P"
            if operator_key.split("-")[2] != expected_env:
                raise ValueError(
                    f"Operator key does not match the expected environment ({expected_env})."
                )
        return True

    def validate_connectivity(self) -> None:
        """ Validates that the core and opt-out URLs are accessible."""
        try:
            core_url = self.configs["core_base_url"]
            optout_url = self.configs["optout_base_url"]
            core_ip = self.__resolve_hostname(core_url)
            requests.get(core_url, timeout=5)
            optout_ip = self.__resolve_hostname(optout_url)
            requests.get(optout_url, timeout=5)
        except (requests.ConnectionError, requests.Timeout) as e:
            raise Exception(
                f"Failed to reach required URLs. Consider enabling {core_ip}, {optout_ip} in the egress firewall."
            )
        except Exception as e:
            raise Exception("Failed to reach the URLs.") from e
        
    
    @abstractmethod
    def _get_secret(self, secret_identifier: str) -> ConfidentialComputeConfig:
        """
        Fetches the secret from a secret store.

        Raises:
            SecretNotFoundException: If the secret is not found.
        """
        pass

    @abstractmethod
    def _setup_auxiliaries(self) -> None:
        """ Sets up auxiliary processes required for confidential computing. """
        pass

    @abstractmethod
    def _validate_auxiliaries(self) -> None:
        """ Validates auxiliary services are running."""
        pass

    @abstractmethod
    def run_compute(self) -> None:
        """ Runs confidential computing."""
        pass

    @staticmethod
    def __resolve_hostname(url: str) -> str:
        """ Resolves the hostname of a URL to an IP address."""
        hostname = urlparse(url).netloc
        return socket.gethostbyname(hostname)

    @staticmethod
    def run_command(command, seperate_process=False):
        print(f"Running command: {' '.join(command)}")
        try:
            if seperate_process:
                subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(command,check=True)
        except Exception as e:
            print(f"Failed to run command: {str(e)}")
            raise RuntimeError (f"Failed to start {' '.join(command)} ")

class ConfidentialComputeMissingConfigError(Exception):
    """Custom exception to handle missing config keys."""
    def __init__(self, missing_keys):
        self.missing_keys = missing_keys
        self.message = f"Missing configuration keys: {', '.join(missing_keys)}"
        super().__init__(self.message)

class SecretNotFoundException(Exception):
    """Custom exception if secret manager is not found"""
    def __init__(self, name):
        self.message = f"Secret manager not found - {name}"
        super().__init__(self.message)
