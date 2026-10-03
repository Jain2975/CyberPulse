"""tests/test_validator.py — Unit tests for ValidatorAgent"""
import pytest
from unittest.mock import patch, MagicMock
from agents.validator_agent import ValidatorAgent, CONFIRMATION_RULES, SEVERITY_CVSS


@pytest.fixture
def validator():
    return ValidatorAgent(target_url="http://localhost:5000", timeout=5, confirm_retries=1)


def test_confirmation_rules_exist():
    assert "sql_injection" in CONFIRMATION_RULES
    assert "path_traversal" in CONFIRMATION_RULES
    assert "command_injection" in CONFIRMATION_RULES
    assert "broken_jwt" in CONFIRMATION_RULES


def test_severity_cvss_scores():
    assert SEVERITY_CVSS["sql_injection"][0] == "CRITICAL"
    assert SEVERITY_CVSS["sql_injection"][1] >= 9.0


def test_validate_confirmed(validator):
    """POTENTIAL_SUCCESS with matched indicators and reconfirm → CONFIRMED"""
    exploit = {
        "id": "sqli_001_sqli_login",
        "type": "sql_injection",
        "endpoint": "/login",
        "method": "POST",
        "payload": "' OR '1'='1",
        "payload_id": "sqli_001",
        "request_data": {"username": "' OR '1'='1", "password": "x"},
        "response_status": 200,
        "response_body": '{"message": "Welcome admin", "token": "abc"}',
        "indicators": ["welcome_message", "jwt_token_returned"],
        "raw_outcome": "POTENTIAL_SUCCESS"
    }
    with patch.object(validator, "_reconfirm", return_value=True):
        finding = validator._validate_exploit(exploit)
    assert finding["status"] == "CONFIRMED"
    assert finding["severity"] == "CRITICAL"
    assert "remediation_hint" in finding


def test_validate_failed(validator):
    """FAILED exploit → stays FAILED regardless of reconfirm."""
    exploit = {
        "id": "sqli_002_sqli_login",
        "type": "sql_injection",
        "endpoint": "/login",
        "method": "POST",
        "payload": "' UNION SELECT 1,2,3--",
        "payload_id": "sqli_002",
        "request_data": {"username": "' UNION SELECT 1,2,3--", "password": "x"},
        "response_status": 401,
        "response_body": '{"status": "fail"}',
        "indicators": [],
        "raw_outcome": "FAILED"
    }
    finding = validator._validate_exploit(exploit)
    assert finding["status"] == "FAILED"


def test_validate_partial(validator):
    """POTENTIAL_SUCCESS with indicators but reconfirm fails → PARTIAL"""
    exploit = {
        "id": "jwt_001_jwt_profile",
        "type": "broken_jwt",
        "endpoint": "/api/profile",
        "method": "GET",
        "payload": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "payload_id": "jwt_001",
        "response_status": 200,
        "response_body": '{"user": {"role": "admin"}}',
        "indicators": ["admin_role_confirmed"],
        "raw_outcome": "POTENTIAL_SUCCESS"
    }
    with patch.object(validator, "_reconfirm", return_value=False):
        finding = validator._validate_exploit(exploit)
    assert finding["status"] == "PARTIAL"
