import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict


class OperatorConfig(TypedDict):
    enclave_memory_mb: int
    enclave_cpu_count: int
    debug_mode: bool
    api_token: str
    core_base_url: str
    optout_base_url: str


class ConfidentialCompute(ABC):
    @abstractmethod
    def _get_secret(self, secret_identifier: str) -> OperatorConfig:
        """
        Fetches the secret from a secret store.

        Raises:
            SecretNotFoundException: If the secret is not found.
        """
        pass

    def validate_operator_key(self, secrets: OperatorConfig) -> bool:
        """ Validates the operator key format and its environment alignment."""
        api_token = secrets.get("api_token")
        if not api_token:
            raise ValueError("API token is missing from the configuration.")

        pattern = r"^(UID2|EUID)-.\-(I|P)-\d+-\*$"
        if re.match(pattern, api_token):
            env = secrets.get("environment", "").lower()
            debug_mode = secrets.get("debug_mode", False)
            expected_env = "I" if debug_mode or env == "integ" else "P"
            if api_token.split("-")[2] != expected_env:
                raise ValueError(
                    f"Operator key does not match the expected environment ({expected_env})."
                )
        return True
    
    @staticmethod
    def __resolve_hostname(url: str) -> str:
        """ Resolves the hostname of a URL to an IP address."""
        hostname = urlparse(url).netloc
        return socket.gethostbyname(hostname)

    def validate_connectivity(self, config: OperatorConfig) -> None:
        """ Validates that the core and opt-out URLs are accessible."""
        try:
            core_url = config["core_base_url"]
            optout_url = config["optout_base_url"]
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