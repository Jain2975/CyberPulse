"""
tests/test_sast.py — Unit tests for the Semgrep SAST agent.

No Semgrep installation is required: the subprocess layer is monkeypatched, so
these tests validate command construction, JSON normalization and the graceful
"skipped" path on every platform.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.patching_agent import SAST_RULE_TO_TYPE  # noqa: E402
from agents.sast_agent import SEVERITY_MAP, SastAgent  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────

SEMGREP_JSON = {
    "version": "1.159.0",
    "results": [
        {
            "check_id": "configs.semgrep.cyberpulse.sql-injection-fstring",
            "path": "vulnapp/app.py",
            "start": {"line": 104, "col": 13},
            "end": {"line": 104, "col": 60},
            "extra": {
                "message": "SQL query built with an f-string and executed",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                    "owasp": ["A03:2021 - Injection"],
                    "confidence": "HIGH",
                },
            },
        },
        {
            "check_id": "configs.semgrep.cyberpulse.path-traversal-unvalidated-open",
            "path": "vulnapp/app.py",
            "start": {"line": 139, "col": 5},
            "end": {"line": 141, "col": 20},
            "extra": {
                "message": "File path built with os.path.join",
                "severity": "WARNING",
                "metadata": {"cwe": ["CWE-22"], "confidence": "MEDIUM"},
            },
        },
        {
            "check_id": "configs.semgrep.cyberpulse.flask-debug-enabled",
            "path": "vulnapp/app.py",
            "start": {"line": 258, "col": 5},
            "end": {"line": 258, "col": 40},
            "extra": {"message": "Flask debug mode", "severity": "INFO", "metadata": {}},
        },
    ],
    "paths": {"scanned": ["vulnapp/app.py"]},
    "errors": [],
}


@pytest.fixture
def sast():
    return SastAgent(scan_paths=["vulnapp"])


# ── Runner detection ──────────────────────────────────────────────────────────

def test_detect_runner_prefers_native(monkeypatch):
    monkeypatch.setattr("agents.sast_agent.shutil.which",
                        lambda name: "/usr/bin/semgrep" if name == "semgrep" else "/usr/bin/docker")
    assert SastAgent._detect_runner() == "native"


def test_detect_runner_falls_back_to_docker(monkeypatch):
    monkeypatch.setattr("agents.sast_agent.shutil.which",
                        lambda name: "/usr/bin/docker" if name == "docker" else None)
    assert SastAgent._detect_runner() == "docker"


def test_detect_runner_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr("agents.sast_agent.shutil.which", lambda name: None)
    assert SastAgent._detect_runner() is None


# ── Command construction ──────────────────────────────────────────────────────

def test_build_command_native(sast, tmp_path):
    cfg = tmp_path / "rules.yml"
    cfg.write_text("rules: []", encoding="utf-8")
    cmd = sast._build_command("native", [Path("vulnapp")], cfg)

    assert cmd[0] == "semgrep"
    assert "--json" in cmd
    assert "--output" in cmd
    assert "--config" in cmd
    assert "vulnapp" in cmd
    assert "docker" not in cmd


def test_build_command_docker_mounts_repo_read_only(sast, tmp_path):
    cfg = tmp_path / "rules.yml"
    cfg.write_text("rules: []", encoding="utf-8")
    cmd = sast._build_command("docker", [Path("vulnapp")], cfg)

    assert cmd[:3] == ["docker", "run", "--rm"]
    joined = " ".join(cmd)
    assert ":/src:ro" in joined
    assert sast.image in cmd
    assert cmd[cmd.index(sast.image) + 1] == "semgrep"


def test_build_command_includes_extra_rulesets(tmp_path):
    agent = SastAgent(scan_paths=["vulnapp"], rulesets=["p/python"])
    cfg = tmp_path / "rules.yml"
    cfg.write_text("rules: []", encoding="utf-8")
    cmd = agent._build_command("native", [Path("vulnapp")], cfg)
    assert cmd.count("--config") == 2
    assert "p/python" in cmd


# ── Normalization ─────────────────────────────────────────────────────────────

def test_normalize_maps_severity_and_cwe(sast):
    finding = sast._normalize(SEMGREP_JSON["results"][0])
    assert finding["severity"] == "HIGH"          # ERROR → HIGH
    assert finding["cwe"] == "CWE-89"             # extracted from the long form
    assert finding["owasp"] == "A03:2021 - Injection"
    assert finding["file"] == "vulnapp/app.py"
    assert finding["line"] == 104
    assert finding["confidence"] == "HIGH"


# ── End-to-end (subprocess mocked) ────────────────────────────────────────────

def _fake_execute_factory(payload, rc=0, stderr=""):
    """Simulate Semgrep writing its JSON report to --output."""
    def _fake_execute(cmd):
        out_idx = cmd.index("--output") + 1
        Path(cmd[out_idx]).write_text(json.dumps(payload), encoding="utf-8")
        return rc, "", stderr
    return _fake_execute


def test_run_produces_complete_report(sast, monkeypatch):
    monkeypatch.setattr(SastAgent, "_detect_runner", staticmethod(lambda: "native"))
    monkeypatch.setattr(sast, "_execute", _fake_execute_factory(SEMGREP_JSON))
    monkeypatch.setattr(sast, "_native_version", staticmethod(lambda: "1.159.0"))

    result = sast.run()

    assert result["status"] == "complete"
    assert result["summary"]["total"] == 3
    assert result["summary"]["by_severity"]["HIGH"] == 1
    assert result["scan_paths"] == ["vulnapp"]
    assert result["tool"] == "semgrep 1.159.0"
    assert len(result["findings"]) == 3
    # sorted worst-first
    assert result["findings"][0]["severity"] == "HIGH"
    # temp report file must not be left behind
    assert not (Path.cwd() / "state" / ".semgrep_tmp.json").exists()


def test_run_handles_exit_code_1_as_findings(sast, monkeypatch):
    """Semgrep exits 1 when findings exist — that is success, not failure."""
    monkeypatch.setattr(SastAgent, "_detect_runner", staticmethod(lambda: "native"))
    monkeypatch.setattr(sast, "_execute", _fake_execute_factory(SEMGREP_JSON, rc=1))

    result = sast.run()
    assert result["status"] == "complete"
    assert result["summary"]["total"] == 3


def test_run_reports_error_on_bad_exit_code(sast, monkeypatch):
    monkeypatch.setattr(SastAgent, "_detect_runner", staticmethod(lambda: "native"))
    monkeypatch.setattr(sast, "_execute",
                        lambda cmd: (7, "", "invalid config: mapping values not allowed"))

    result = sast.run()
    assert result["status"] == "error"
    assert "7" in result["reason"]
    assert "invalid config" in result["detail"]


def test_run_skips_when_tool_missing(sast, monkeypatch):
    monkeypatch.setattr(SastAgent, "_detect_runner", staticmethod(lambda: None))

    result = sast.run()

    assert result["status"] == "skipped"
    assert result["findings"] == []
    assert any("semgrep" in hint for hint in result["install_hints"])


def test_run_errors_when_scan_path_missing(monkeypatch):
    agent = SastAgent(scan_paths=["does_not_exist"])
    result = agent.run()
    assert result["status"] == "error"
    assert "No valid scan paths" in result["reason"]


def test_run_errors_when_config_missing():
    agent = SastAgent(scan_paths=["vulnapp"], config_file="configs/semgrep/nope.yml")
    result = agent.run()
    assert result["status"] == "error"
    assert "Semgrep config not found" in result["reason"]


def test_parse_output_falls_back_to_stdout(sast):
    stdout = "some banner text\n" + json.dumps({"results": [], "paths": {}})
    parsed = sast._parse_output(stdout, "")
    assert parsed is not None
    assert parsed["results"] == []


def test_parse_output_returns_none_for_garbage(sast):
    assert sast._parse_output("not json at all", "nope") is None


def test_state_filename_is_contract_name():
    assert SastAgent(target_url="local").state_filename == "sast_report.json"


def test_output_file_override_isolated_from_original():
    agent = SastAgent(scan_paths=["vulnapp"], output_file="sast_report_patched.json")
    assert agent.state_filename == "sast_report_patched.json"


# ── Config / mapping consistency ──────────────────────────────────────────────

def test_every_semgrep_rule_has_a_patch_mapping():
    """
    Guard: when a rule is added to configs/semgrep/cyberpulse.yml it should be
    mapped in SAST_RULE_TO_TYPE so --patch-sast can act on it.
    """
    import re

    config = (Path(__file__).parent.parent / "configs" / "semgrep" / "cyberpulse.yml")
    rule_ids = re.findall(r"^\s*-\s*id:\s*(\S+)", config.read_text(encoding="utf-8"), re.M)

    assert rule_ids, "no rules parsed from the semgrep config"
    unmapped = [rid for rid in rule_ids if rid not in SAST_RULE_TO_TYPE]
    assert not unmapped, f"semgrep rules without a patch mapping: {unmapped}"


def test_sast_rule_to_type_maps_to_known_patch_handlers():
    known_types = {
        "sql_injection", "path_traversal", "csrf", "command_injection",
        "hardcoded_credentials", "broken_jwt", "flask_secret_key", "runtime_hardening",
    }
    assert set(SAST_RULE_TO_TYPE.values()) <= known_types


def test_normalize_handles_missing_metadata(sast):
    finding = sast._normalize(SEMGREP_JSON["results"][2])
    assert finding["severity"] == "LOW"           # INFO → LOW
    assert finding["cwe"] is None
    assert finding["owasp"] is None


def test_severity_map_covers_semgrep_levels():
    assert SEVERITY_MAP == {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def test_first_cwe_variants():
    assert SastAgent._first_cwe(["CWE-78: Improper..."]) == "CWE-78"
    assert SastAgent._first_cwe("cwe-22") == "CWE-22"
    assert SastAgent._first_cwe(None) is None
    assert SastAgent._first_cwe([]) is None


def test_summarize_counts_and_rules(sast):
    findings = [sast._normalize(r) for r in SEMGREP_JSON["results"]]
    summary = sast._summarize(findings, SEMGREP_JSON, [Path("vulnapp")])

    assert summary["total"] == 3
    assert summary["by_severity"]["HIGH"] == 1
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_severity"]["LOW"] == 1
    assert summary["files_scanned"] == 1
    assert len(summary["rules_triggered"]) == 3
