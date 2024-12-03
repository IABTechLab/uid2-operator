import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict, NotRequired


class ConfidentialComputeConfig(TypedDict):
    enclave_memory_mb: int
    enclave_cpu_count: int
    debug_mode: bool
    operator_key: str
    core_base_url: str
    optout_base_url: str
    environment: str

class OperatorConfig(TypedDict):
    sites_metadata_path: str
    clients_metadata_path: str
    keysets_metadata_path: str
    keyset_keys_metadata_path: str
    salts_metadata_path: str
    services_metadata_path: str
    service_links_metadata_path: str
    optout_metadata_path: str
    core_attest_url: str
    optout_api_uri: str
    optout_s3_folder: str
    identity_token_expires_after_seconds: str
    client_side_keypairs_metadata_path: NotRequired[str]
    
class ConfidentialCompute(ABC):
    @abstractmethod
    def _get_secret(self, secret_identifier: str) -> ConfidentialComputeConfig:
        """
        Fetches the secret from a secret store.

        Raises:
            SecretNotFoundException: If the secret is not found.
        """
        pass

    def validate_operator_key(self, secrets: ConfidentialComputeConfig) -> bool:
        """ Validates the operator key format and its environment alignment."""
        operator_key = secrets.get("operator_key")
        if not operator_key:
            raise ValueError("API token is missing from the configuration.")
        pattern = r"^(UID2|EUID)-.\-(I|P)-\d+-\*$"
        if re.match(pattern, operator_key):
            env = secrets.get("environment", "").lower()
            debug_mode = secrets.get("debug_mode", False)
            expected_env = "I" if debug_mode or env == "integ" else "P"
            if operator_key.split("-")[2] != expected_env:
                raise ValueError(
                    f"Operator key does not match the expected environment ({expected_env})."
                )
        return True
    
    @staticmethod
    def __resolve_hostname(url: str) -> str:
        """ Resolves the hostname of a URL to an IP address."""
        hostname = urlparse(url).netloc
        return socket.gethostbyname(hostname)

    def validate_connectivity(self, config: ConfidentialComputeConfig) -> None:
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
