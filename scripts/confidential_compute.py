import requests
import re
import socket
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from typing import TypedDict, Dict

class OperatorConfig(TypedDict):
    enclave_memory_mb: int
    enclave_cpu_count: int
    debug_mode: bool
    api_token: str
    core_base_url: str
    optout_base_url: str

class ConfidentialCompute(ABC):

    @abstractmethod
    def _get_secret(self, secret_identifier):
        """
        Gets the secret from secret store

        Raises: 
            SecretNotFoundException: Points to public documentation
        """
        pass

    def validate_operator_key(self, secrets: OperatorConfig):
        """
        Validates operator key if following new pattern. Ignores otherwise
        """
        api_token = secrets.get('api_token', None)
        pattern = r"^(UID2|EUID)-.\-(I|P)-\d+-\*$"
        if bool(re.match(pattern, api_token)):
            if secrets.get('debug_mode', False) or secrets.get('environment') == 'integ':
                if api_token.split('-')[2] != 'I':
                    raise Exception("Operator key does not match the environment")
            else:
                if api_token.split('-')[2] != 'P':
                    raise Exception("Operator key does not match the environment")
        return True

    def validate_connectivity(self, config: OperatorConfig):
        """
        Validates core/optout is accessible. 
        """
        try:
            core_ip = socket.gethostbyname(urlparse(config['core_base_url']).netloc)
            requests.get(config['core_base_url'], timeout=5)
            optout_ip = socket.gethostbyname(urlparse(config['optout_base_url']).netloc)
            requests.get(config['optout_base_url'], timeout=5)
        except (requests.ConnectionError, requests.Timeout) as e :
            raise Exception("Failed to reach the URL. -- ERROR CODE, enable IPs? {} {}".format(core_ip, optout_ip), e)
        except Exception as e:
            raise Exception("Failed to reach the URL. ")
        """
            s3 does not have static IP, and the range returned for s3 is huge to validate. 
            r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
            ips = list(map(lambda x: x['ip_prefix'], filter(lambda x: x['region']=='us-east-1' and x['service'] == 'S3', r.json()['prefixes'])))
        """
        return
    
    @abstractmethod
    def _setup_auxiliaries(self):
        """
        Sets up auxilary processes required to confidential compute
        """
        pass

    @abstractmethod
    def _validate_auxiliaries(self):
        """
        Validates auxilary services are running
        """
        pass

    @abstractmethod
    def run_compute(self):
        """
        Runs compute.
        """
        pass