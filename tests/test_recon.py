"""tests/test_recon.py — Unit tests for ReconAgent"""
import json
import pytest
from unittest.mock import MagicMock, patch
from agents.recon_agent import ReconAgent


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, url="", content=b""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "application/json"}
        self.url = url
        self.content = content or text.encode()

    def json(self):
        return json.loads(self.text)


@pytest.fixture
def recon_agent():
    agent = ReconAgent(target_url="http://localhost:5000", timeout=5, port_scan=False)
    return agent


def test_recon_agent_initializes(recon_agent):
    assert recon_agent.name == "ReconAgent"
    assert recon_agent.target_url == "http://localhost:5000"


def test_fingerprint_stack_detects_flask(recon_agent):
    with patch.object(recon_agent, "safe_request") as mock_req:
        mock_req.return_value = MockResponse(
            status_code=200,
            text='{"app": "VulnApp"}',
            headers={"Content-Type": "application/json", "Server": "Werkzeug/2.3.7 Python/3.11"},
            url="http://localhost:5000/"
        )
        stack = recon_agent._fingerprint_stack()
        assert "server" in stack
        assert "Werkzeug" in stack.get("server", "") or "Python" in stack.get("server", "")


def test_catalog_attack_vectors_finds_sqli(recon_agent):
    endpoints = [
        {"path": "/login", "methods": ["GET", "POST"], "content_type": "text/html",
         "status": 200, "content_length": 100, "redirect": None, "body_preview": ""}
    ]
    forms = []
    vectors = recon_agent._catalog_attack_vectors(endpoints, forms)
    sqli_vectors = [v for v in vectors if v["type"] == "sql_injection"]
    assert len(sqli_vectors) > 0
    assert sqli_vectors[0]["severity"] == "CRITICAL"


def test_catalog_attack_vectors_finds_path_traversal(recon_agent):
    endpoints = [
        {"path": "/file", "methods": ["GET"], "content_type": "application/json",
         "status": 200, "content_length": 50, "redirect": None, "body_preview": ""}
    ]
    vectors = recon_agent._catalog_attack_vectors(endpoints, [])
    pt_vectors = [v for v in vectors if v["type"] == "path_traversal"]
    assert len(pt_vectors) > 0


def test_audit_headers_marks_missing(recon_agent):
    with patch.object(recon_agent, "safe_request") as mock_req:
        mock_req.return_value = MockResponse(
            status_code=200,
            text="{}",
            headers={"Content-Type": "application/json"},
            url="http://localhost:5000/"
        )
        headers = recon_agent._audit_headers()
        assert headers.get("Content-Security-Policy") == "MISSING"
        assert headers.get("X-Frame-Options") == "MISSING"
