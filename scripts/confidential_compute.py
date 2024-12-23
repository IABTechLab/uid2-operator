import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict, NotRequired, get_type_hints
import subprocess

class ConfidentialComputeConfig(TypedDict):
    api_token: str
    core_base_url: str
    optout_base_url: str
    environment: str
    skip_validations: NotRequired[bool]
    debug_mode: NotRequired[bool]
    
class ConfidentialCompute(ABC):

    def __init__(self):
        self.configs: ConfidentialComputeConfig = {}

    def validate_configuration(self):
        """ Validates the paramters specified through configs/secret manager ."""
        print("Validating configurations provided")
        def validate_operator_key():
            """ Validates the operator key format and its environment alignment."""
            operator_key = self.configs.get("api_token")
            if not operator_key:
                raise ValueError("API token is missing from the configuration.")
            pattern = r"^(UID2|EUID)-.\-(I|P|L)-\d+-.*$"
            if re.match(pattern, operator_key):
                env = self.configs.get("environment", "").lower()
                debug_mode = self.configs.get("debug_mode", False)
                expected_env = "I" if debug_mode or env == "integ" else "P"
                
                if operator_key.split("-")[2] != expected_env:
                    raise ValueError(
                        f"Operator key does not match the expected environment ({expected_env})."
                    )
                print("Validated operator key matches environment")
            else:
                print("Skipping operator key validation")

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
            print(f"Validated {self.configs[url_key]} matches other config parameters")
            
            
        def validate_connectivity() -> None:
            """ Validates that the core URL is accessible."""
            try:
                core_url = self.configs["core_base_url"]
                core_ip = socket.gethostbyname(urlparse(core_url).netloc)
                requests.get(core_url, timeout=5)
                print(f"Validated connectivity to {core_url}")
            except (requests.ConnectionError, requests.Timeout) as e:
                raise RuntimeError(
                    f"Failed to reach required URLs. Consider enabling {core_ip} in the egress firewall."
                )
            except Exception as e:
                raise Exception("Failed to reach the URLs.") from e
        type_hints = get_type_hints(ConfidentialComputeConfig, include_extras=True)
        required_keys = [field for field, hint in type_hints.items() if "NotRequired" not in str(hint)]
        missing_keys = [key for key in required_keys if key not in self.configs]
        if missing_keys:
            raise MissingConfigError(missing_keys)
            
        environment = self.configs["environment"]

        if environment not in ["integ", "prod"]:
            raise ValueError("Environment must be either prod/integ. It is currently set to", environment)

        if self.configs.get("debug_mode") and environment == "prod":
            raise ValueError("Debug mode cannot be enabled in the production environment.")
        
        validate_url("core_base_url", environment)
        validate_url("optout_base_url", environment)
        validate_operator_key()
        validate_connectivity()
        print("Completed static validation of confidential compute config values")
        

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
        
class ConfidentialComputeStartupException(Exception):
    def __init__(self, message):
        super().__init__(message)

class MissingConfigError(ConfidentialComputeStartupException):
    """Custom exception to handle missing config keys."""
    def __init__(self, missing_keys):
        self.missing_keys = missing_keys
        self.message = f"\n Missing configuration keys: {', '.join(missing_keys)} \n"
        super().__init__(self.message)

class SecretNotFoundException(ConfidentialComputeStartupException):
    """Custom exception if secret manager is not found"""
    def __init__(self, name):
        self.message = f"Secret manager not found - {name}. Please check if secret exist and the Instance Profile has permission to read it"
        super().__init__(self.message)
