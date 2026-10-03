"""
tests/test_dast.py — Unit tests for the OWASP ZAP DAST agent.

Docker is not required: the subprocess layer is monkeypatched, so command
construction, report normalization and the "skipped" path are all covered.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import agents.dast_agent as dast_mod  # noqa: E402
from agents.dast_agent import RISK_MAP, DastAgent  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────

ZAP_JSON = {
    "@version": "2.15.0",
    "site": [
        {
            "@name": "http://localhost:5000",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "2",
                    "cweid": "89",
                    "count": "2",
                    "desc": "<p>SQL injection may be possible.</p>",
                    "solution": "<p>Use <b>parameterized</b> queries.</p>",
                    "instances": [
                        {"uri": "http://localhost:5000/login", "method": "POST",
                         "evidence": "SQL syntax error"},
                        {"uri": "http://localhost:5000/login?u=1", "method": "GET"},
                    ],
                },
                {
                    "pluginid": "10020",
                    "alert": "Missing Anti-clickjacking Header",
                    "riskcode": "2",
                    "confidence": "3",
                    "cweid": "1021",
                    "count": "1",
                    "desc": "<p>X-Frame-Options missing</p>",
                    "solution": "<p>Add the header.</p>",
                    "instances": [{"uri": "http://localhost:5000/", "method": "GET"}],
                },
                {
                    "pluginid": "10096",
                    "alert": "Timestamp Disclosure",
                    "riskcode": "1",
                    "confidence": "1",
                    "cweid": "200",
                    "count": "1",
                    "desc": "info",
                    "solution": "n/a",
                    "instances": [{"uri": "http://localhost:5000/", "method": "GET"}],
                },
            ],
        }
    ],
}


@pytest.fixture
def dast(monkeypatch, tmp_path):
    """Agent wired to an isolated ZAP work dir so tests cannot leak reports."""
    monkeypatch.setattr(dast_mod, "ZAP_WORK_DIR", tmp_path / "zap")
    return DastAgent(target_url="http://localhost:5000")

# ── Networking / platform handling ────────────────────────────────────────────

def test_network_mode_host_on_linux(monkeypatch, dast):
    monkeypatch.setattr(dast_mod.platform, "system", lambda: "Linux")
    assert dast._resolve_network_mode() == "host"


def test_network_mode_bridge_on_windows(monkeypatch, dast):
    monkeypatch.setattr(dast_mod.platform, "system", lambda: "Windows")
    assert dast._resolve_network_mode() is None


def test_network_mode_explicit_override(dast):
    dast.network_mode = "bridge"
    assert dast._resolve_network_mode() is None
    dast.network_mode = "host"
    assert dast._resolve_network_mode() == "host"


def test_container_target_rewrites_localhost_for_docker_desktop(dast):
    assert dast._container_target(None) == "http://host.docker.internal:5000"


def test_container_target_rewrites_127_0_0_1(dast):
    dast.target_url = "http://127.0.0.1:5000"
    assert dast._container_target(None) == "http://host.docker.internal:5000"


def test_container_target_untouched_with_host_networking(dast):
    assert dast._container_target("host") == "http://localhost:5000"


def test_container_target_keeps_non_local_hosts():
    agent = DastAgent(target_url="http://vulnapp:5000")
    assert agent._container_target(None) == "http://vulnapp:5000"


# ── Command construction ──────────────────────────────────────────────────────

def test_build_command_baseline_includes_required_flags(dast):
    cmd = dast._build_command(None, "http://host.docker.internal:5000",
                              "zap_report_baseline.json", "r.html", "r.md")
    joined = " ".join(cmd)

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "zap-baseline.py" in cmd
    assert "ghcr.io/zaproxy/zaproxy:stable" in cmd
    assert "-t" in cmd and "http://host.docker.internal:5000" in cmd
    assert "-J" in cmd and "-r" in cmd and "-w" in cmd
    assert "-I" in cmd                     # tolerate warnings
    assert ":/zap/wrk:rw" in joined        # report output dir
    assert ":/zap/configs:ro" in joined    # scan policy mounted read-only
    assert "localhost" not in joined       # rewritten for the container


def test_build_command_full_scan_uses_full_script(dast):
    dast.scan_type = "full"
    cmd = dast._build_command("host", "http://localhost:5000", "j", "h", "m")
    assert "zap-full-scan.py" in cmd
    assert "--network" in cmd and "host" in cmd


def test_scan_type_is_validated():
    assert DastAgent(target_url="http://x", scan_type="nonsense").scan_type == "baseline"
    assert DastAgent(target_url="http://x", scan_type="full").scan_type == "full"

# ── Normalization ─────────────────────────────────────────────────────────────

def test_normalize_high_risk_alert(dast):
    alert = ZAP_JSON["site"][0]["alerts"][0]
    f = dast._normalize(alert, ZAP_JSON["site"][0])

    assert f["severity"] == "HIGH"           # riskcode 3
    assert f["cwe"] == "CWE-89"
    assert f["confidence"] == "MEDIUM"       # confidence 2
    assert f["instances"] == 2
    assert f["endpoint"] == "http://localhost:5000/login"
    assert "<p>" not in f["description"]     # HTML stripped
    assert "parameterized" in f["solution"]


def test_normalize_medium_alert(dast):
    f = dast._normalize(ZAP_JSON["site"][0]["alerts"][1], ZAP_JSON["site"][0])
    assert f["severity"] == "MEDIUM"
    assert f["cwe"] == "CWE-1021"


def test_normalize_low_alert(dast):
    f = dast._normalize(ZAP_JSON["site"][0]["alerts"][2], ZAP_JSON["site"][0])
    assert f["severity"] == "LOW"


def test_normalize_alert_without_cwe(dast):
    alert = {"pluginid": "1", "alert": "X", "riskcode": "0", "cweid": "0", "instances": []}
    f = dast._normalize(alert, {"@name": "http://localhost:5000"})
    assert f["cwe"] is None
    assert f["severity"] == "INFO"
    assert f["endpoint"] == "http://localhost:5000"


def test_risk_map_covers_all_codes():
    assert RISK_MAP == {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def test_iter_alerts_accepts_single_site_object():
    raw = {"site": {"@name": "http://x", "alerts": [{"alert": "a"}]}}
    pairs = list(DastAgent._iter_alerts(raw))
    assert len(pairs) == 1
    assert pairs[0][1][0]["alert"] == "a"


def test_summarize_counts_and_urls(dast):
    findings = [dast._normalize(a, s)
                for s, alerts in dast._iter_alerts(ZAP_JSON) for a in alerts]
    summary = dast._summarize(ZAP_JSON, findings)

    assert summary["total_alerts"] == 3
    assert summary["by_risk"]["HIGH"] == 1
    assert summary["by_risk"]["MEDIUM"] == 1
    assert summary["by_risk"]["LOW"] == 1
    assert summary["urls_scanned"] >= 2


def test_strip_html_removes_tags_and_collapses_space(dast):
    assert dast._strip_html("<p>Hello <b>world</b></p>\n\n") == "Hello world"


# ── End-to-end (subprocess mocked) ────────────────────────────────────────────

def _fake_docker_factory(payload, rc=0, write_report=True):
    """Simulate ZAP writing its JSON report into the mounted work dir."""
    def _fake_execute(cmd):
        if write_report:
            idx = cmd.index("-J") + 1
            (dast_mod.ZAP_WORK_DIR / cmd[idx]).write_text(
                json.dumps(payload), encoding="utf-8"
            )
        return rc, "ZAP scan complete", ""
    return _fake_execute


def test_run_produces_complete_report(dast, monkeypatch):
    monkeypatch.setattr(dast_mod.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dast, "_execute", _fake_docker_factory(ZAP_JSON))

    result = dast.run()

    assert result["status"] == "complete"
    assert result["tool"] == "OWASP ZAP 2.15.0"
    assert result["summary"]["total_alerts"] == 3
    assert result["summary"]["by_risk"]["HIGH"] == 1
    assert result["findings"][0]["severity"] == "HIGH"      # worst first
    assert result["reports"]["json"].endswith("zap_report_baseline.json")


def test_run_skips_when_docker_missing(dast, monkeypatch):
    monkeypatch.setattr(dast_mod.shutil, "which", lambda name: None)

    result = dast.run()

    assert result["status"] == "skipped"
    assert "docker" in result["reason"]
    assert any("ghcr.io/zaproxy" in h for h in result["install_hints"])
    assert result["findings"] == []


def test_run_reports_error_when_zap_fails(dast, monkeypatch):
    monkeypatch.setattr(dast_mod.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dast, "_execute",
                        _fake_docker_factory({}, rc=3, write_report=False))

    result = dast.run()
    assert result["status"] == "error"
    assert "ZAP exited 3" in result["reason"]


def test_run_error_when_no_report_written(dast, monkeypatch):
    """Exit code 0 but no report file is still a failure to capture results."""
    monkeypatch.setattr(dast_mod.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dast, "_execute", lambda cmd: (0, "ok", ""))

    result = dast.run()
    assert result["status"] == "error"
    assert "no readable JSON report" in result["reason"]


def test_run_tolerates_nonzero_warning_exit_with_report(dast, monkeypatch):
    """zap-baseline exits 1/2 for warnings/failures — still a usable report."""
    monkeypatch.setattr(dast_mod.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dast, "_execute", _fake_docker_factory(ZAP_JSON, rc=2))

    result = dast.run()
    assert result["status"] == "complete"
    assert result["summary"]["total_alerts"] == 3


def test_api_scan_type_is_skipped(dast):
    dast.scan_type = "api"
    result = dast.run()
    assert result["status"] == "skipped"
    assert "OpenAPI" in result["reason"]


def test_state_filenames_are_contract_names():
    assert DastAgent(target_url="http://x").state_filename == "dast_report.json"
    assert DastAgent(target_url="http://x",
                     output_file="dast_report_patched.json").state_filename == \
        "dast_report_patched.json"


