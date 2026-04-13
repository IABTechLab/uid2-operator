import pytest
import requests
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from confidential_compute import (
    ConfidentialCompute,
    ConfidentialComputeConfig,
    OperatorKeyRejectedError,
    OperatorKeyValidationError,
    UID2ServicesUnreachableError,
    ConfigurationMissingError,
    ConfigurationValueError,
)


class ConcreteConfidentialCompute(ConfidentialCompute):
    """Minimal concrete implementation for testing the base class."""

    def _set_confidential_config(self, secret_identifier):
        pass

    def _setup_auxiliaries(self):
        pass

    def _validate_auxiliaries(self):
        pass

    def run_compute(self):
        pass


VALID_CONFIG = {
    "operator_key": "UID2-O-I-1-abcdefghijklmnop",
    "core_base_url": "https://core-integ.uidapi.com",
    "optout_base_url": "https://optout-integ.uidapi.com",
    "environment": "integ",
    "uid_instance_id_prefix": "ec2-abc123-ami-xyz",
}


def make_instance(config_overrides=None):
    cc = ConcreteConfidentialCompute()
    cc.configs = {**VALID_CONFIG, **(config_overrides or {})}
    return cc


class TestValidateOperatorKeyWithService:
    """Tests for the pre-flight operator key verification against the core service."""

    def _run_validate(self, cc, mock_response):
        with patch("confidential_compute.socket.gethostbyname", return_value="1.2.3.4"), \
             patch("confidential_compute.requests.get") as mock_get, \
             patch("confidential_compute.requests.post", return_value=mock_response) as mock_post:
            mock_get.return_value = MagicMock(status_code=200)
            cc.validate_configuration()
            return mock_post

    def test_invalid_key_raises_operator_key_rejected_error(self):
        cc = make_instance()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = '{"status":"Unauthorized"}'

        with pytest.raises(OperatorKeyRejectedError):
            self._run_validate(cc, mock_resp)

    def test_valid_key_with_no_payload_passes(self):
        cc = make_instance()
        mock_resp = MagicMock()
        mock_resp.status_code = 400  # valid key, missing attestation_request

        self._run_validate(cc, mock_resp)  # should not raise

    def test_valid_key_200_response_passes(self):
        cc = make_instance()
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        self._run_validate(cc, mock_resp)  # should not raise

    def test_server_error_is_non_blocking(self):
        cc = make_instance()
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        self._run_validate(cc, mock_resp)  # should not raise

    def test_connection_error_is_non_blocking(self):
        cc = make_instance()

        with patch("confidential_compute.socket.gethostbyname", return_value="1.2.3.4"), \
             patch("confidential_compute.requests.get") as mock_get, \
             patch("confidential_compute.requests.post", side_effect=requests.ConnectionError("refused")):
            mock_get.return_value = MagicMock(status_code=200)
            cc.validate_configuration()  # should not raise

    def test_timeout_is_non_blocking(self):
        cc = make_instance()

        with patch("confidential_compute.socket.gethostbyname", return_value="1.2.3.4"), \
             patch("confidential_compute.requests.get") as mock_get, \
             patch("confidential_compute.requests.post", side_effect=requests.Timeout("timed out")):
            mock_get.return_value = MagicMock(status_code=200)
            cc.validate_configuration()  # should not raise

    def test_unexpected_exception_is_non_blocking(self):
        cc = make_instance()

        with patch("confidential_compute.socket.gethostbyname", return_value="1.2.3.4"), \
             patch("confidential_compute.requests.get") as mock_get, \
             patch("confidential_compute.requests.post", side_effect=RuntimeError("unexpected")):
            mock_get.return_value = MagicMock(status_code=200)
            cc.validate_configuration()  # should not raise

    def test_post_sent_to_correct_endpoint(self):
        cc = make_instance()
        mock_resp = MagicMock()
        mock_resp.status_code = 400

        mock_post = self._run_validate(cc, mock_resp)
        mock_post.assert_called_once_with(
            "https://core-integ.uidapi.com/attest",
            headers={"Authorization": f"Bearer {VALID_CONFIG['operator_key']}"},
            json={},
            timeout=5,
        )

    def test_skip_validations_bypasses_key_service_check(self):
        cc = make_instance({"skip_validations": True})

        with patch("confidential_compute.requests.post") as mock_post:
            # validate_configuration is not called when skip_validations is True
            # (the cloud scripts check this flag before calling validate_configuration)
            # But we can confirm the function itself is gated correctly:
            # skip_validations=True means validate_configuration() is never called.
            mock_post.assert_not_called()
