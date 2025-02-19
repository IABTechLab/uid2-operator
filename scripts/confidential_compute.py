import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict, NotRequired, get_type_hints
import subprocess
import logging

class ConfidentialComputeConfig(TypedDict):
    operator_key: str
    core_base_url: str
    optout_base_url: str
    environment: str
    skip_validations: NotRequired[bool]
    debug_mode: NotRequired[bool]

class ConfidentialComputeStartupError(Exception):
    def __init__(self, error_name, provider, extra_message=None):
        urls = {
            "EC2EntryPoint": "https://unifiedid.com/docs/guides/operator-guide-aws-marketplace#uid2-operator-error-codes",
            "AzureEntryPoint": "https://unifiedid.com/docs/guides/operator-guide-azure-enclave#uid2-operator-error-codes",
            "GCPEntryPoint": "https://unifiedid.com/docs/guides/operator-private-gcp-confidential-space#uid2-operator-error-codes",
        }
        url = urls.get(provider)
        super().__init__(f"{error_name}\n" + (extra_message if extra_message else "") + f"\nVisit {url} for more details")

class InstanceProfileMissingError(ConfidentialComputeStartupError):
    def __init__(self, cls, message = None):
        super().__init__(error_name=f"E01: {self.__class__.__name__}", provider=cls, extra_message=message)

class OperatorKeyNotFoundError(ConfidentialComputeStartupError):
    def __init__(self, cls, message = None):
        super().__init__(error_name=f"E02: {self.__class__.__name__}", provider=cls, extra_message=message)

class ConfigurationMissingError(ConfidentialComputeStartupError):
    def __init__(self, cls, missing_keys):
        super().__init__(error_name=f"E03: {self.__class__.__name__}", provider=cls, extra_message=', '.join(missing_keys))

class ConfigurationValueError(ConfidentialComputeStartupError):
    def __init__(self, cls, config_key = None):
        super().__init__(error_name=f"E04: {self.__class__.__name__} " , provider=cls, extra_message=config_key)

class OperatorKeyValidationError(ConfidentialComputeStartupError):
    def __init__(self, cls):
        super().__init__(error_name=f"E05: {self.__class__.__name__}", provider=cls)

class UID2ServicesUnreachableError(ConfidentialComputeStartupError):
    def __init__(self, cls, ip=None):
        super().__init__(error_name=f"E06: {self.__class__.__name__}", provider=cls, extra_message=ip)

class OperatorKeyPermissionError(ConfidentialComputeStartupError):
    def __init__(self, cls, message = None):
        super().__init__(error_name=f"E08: {self.__class__.__name__}", provider=cls, extra_message=message)

class ConfidentialCompute(ABC):

    def __init__(self):
        self.configs: ConfidentialComputeConfig = {}

    def validate_configuration(self):
        """ Validates the paramters specified through configs/secret manager ."""
        logging.info("Validating configurations provided")
        def validate_operator_key():
            """ Validates the operator key format and its environment alignment."""
            operator_key = self.configs.get("operator_key")
            pattern = r"^(UID2|EUID)-.\-(I|P|L)-\d+-.*$"
            if re.match(pattern, operator_key):
                env = self.configs.get("environment", "").lower()
                debug_mode = self.configs.get("debug_mode", False)
                expected_env = "I" if debug_mode or env == "integ" else "P"
                if operator_key.split("-")[2] != expected_env:
                    raise OperatorKeyValidationError(self.__class__.__name__)
                logging.info("Validated operator key matches environment")
            else:
                logging.info("Skipping operator key validation")

        def validate_url(url_key, environment):
            """URL should include environment except in prod"""
            if environment != "prod" and environment not in self.configs[url_key]:
                raise ConfigurationValueError(self.__class__.__name__, url_key)
            parsed_url = urlparse(self.configs[url_key])
            if parsed_url.scheme != 'https' and parsed_url.path:
                raise ConfigurationValueError(self.__class__.__name__, url_key)
            logging.info(f"Validated {self.configs[url_key]} matches other config parameters")
            
        def validate_connectivity() -> None:
            """ Validates that the core URL is accessible."""
            try:
                core_url = self.configs["core_base_url"]
                core_ip = socket.gethostbyname(urlparse(core_url).netloc)
                requests.get(core_url, timeout=5)
                logging.info(f"Validated connectivity to {core_url}")
            except (requests.ConnectionError, requests.Timeout) as e:
                raise UID2ServicesUnreachableError(self.__class__.__name__, core_ip)
            except Exception as e:
                raise UID2ServicesUnreachableError(self.__class__.__name__)
            
        type_hints = get_type_hints(ConfidentialComputeConfig, include_extras=True)
        required_keys = [field for field, hint in type_hints.items() if "NotRequired" not in str(hint)]
        missing_keys = [key for key in required_keys if key not in self.configs]
        if missing_keys:
            raise ConfigurationMissingError(self.__class__.__name__, missing_keys)
        
        environment = self.configs["environment"]
        if environment not in ["integ", "prod"]:
            raise ConfigurationValueError(self.__class__.__name__, "environment")

        if self.configs.get("debug_mode") and environment == "prod":
            raise ConfigurationValueError(self.__class__.__name__, "debug_mode")
        
        print("log environment to see what values ", environment)
        
        validate_url("core_base_url", environment)
        validate_url("optout_base_url", environment)
        validate_operator_key()
        validate_connectivity()
        logging.info("Completed static validation of confidential compute config values")
        
    @abstractmethod
    def _set_confidential_config(self, secret_identifier: str) -> None:
        """
        Set ConfidentialComputeConfig
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
    def run_command(command, separate_process=False):
        logging.info(f"Running command: {' '.join(command)}")
        try:
            if separate_process:
                subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(command,check=True)
        except Exception as e:
            logging.error(f"Failed to run command: {e}", exc_info=True)
            raise RuntimeError (f"Failed to start {' '.join(command)} ")