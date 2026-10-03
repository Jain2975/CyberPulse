"""
tests/test_gui.py — Unit tests for the CyberPulse web dashboard.

These tests exercise the Flask app in-process with a stub PipelineRunner so no
real pipeline is spawned.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from gui.app import PipelineRunner, create_app, markdown_to_html  # noqa: E402


class StubRunner(PipelineRunner):
    """Runner that records start() calls instead of launching a subprocess."""

    def __init__(self):
        super().__init__()
        self.started_with = None

    def start(self, mode, target, patched_target=None, timeout=10, port_scan=True):
        error = self.validate_request(mode, target, patched_target)
        if error:
            return False, error
        self.started_with = {
            "mode": mode, "target": target, "patched_target": patched_target,
            "timeout": timeout, "port_scan": port_scan,
        }
        return True, f"stub started {mode}"

    def stop(self):
        return True, "stub stopped"


@pytest.fixture
def client():
    app = create_app(StubRunner())
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


# ── Routes ────────────────────────────────────────────────────────────────────

def test_dashboard_page_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CyberPulse" in body
    assert "Pipeline Control" in body
    # every CLI mode must be selectable in the UI
    for mode in ("full", "recon-only", "exploit-only", "patch-only", "re-exploit"):
        assert mode in body


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_status_endpoint_exposes_phases(client):
    payload = client.get("/api/status").get_json()
    assert payload["running"] is False
    assert len(payload["phases"]) == 5
    assert [p["num"] for p in payload["phases"]] == [1, 2, 3, 4, 5]
    assert all(p["state"] in ("pending", "active", "done", "skipped") for p in payload["phases"])


def test_run_endpoint_forwards_form_payload(client):
    resp = client.post("/api/run", json={
        "mode": "recon-only", "target": "http://localhost:5000",
        "timeout": 7, "port_scan": False,
    })
    assert resp.status_code == 200
    assert resp.get_json()["started"] is True
    stub = client.application.config["RUNNER"]
    assert stub.started_with["mode"] == "recon-only"
    assert stub.started_with["timeout"] == 7
    assert stub.started_with["port_scan"] is False


def test_run_endpoint_rejects_bad_mode(client):
    resp = client.post("/api/run", json={"mode": "nuke-it", "target": "http://x"})
    assert resp.status_code == 409
    assert resp.get_json()["started"] is False


def test_state_endpoint_blocks_path_traversal(client):
    resp = client.get("/api/state/../../main.py")
    assert resp.status_code in (403, 404)
    assert "main.py" not in resp.get_data(as_text=True) or "not allowed" in resp.get_data(as_text=True)


def test_state_endpoint_forbids_non_contract_file(client):
    resp = client.get("/api/state/secrets.json")
    assert resp.status_code == 403


def test_log_endpoint_returns_offset_shape(client):
    payload = client.get("/api/log?offset=0").get_json()
    assert set(payload) == {"lines", "next_offset", "total"}
    assert isinstance(payload["lines"], list)


def test_dashboard_exposes_scanner_section(client):
    body = client.get("/").get_data(as_text=True)
    assert "SAST &amp; DAST Scans" in body or "SAST & DAST Scans" in body
    assert "sast-only" in body and "dast-only" in body


def test_scanner_state_files_are_allow_listed(client, monkeypatch, tmp_path):
    import gui.app as gui_app

    for name in ("sast_report.json", "sast_report_patched.json",
                 "dast_report.json", "dast_report_patched.json"):
        assert name in gui_app.ALLOWED_STATE_FILES

    (tmp_path / "sast_report.json").write_text(
        '{"status": "complete", "summary": {"total": 6}}', encoding="utf-8")
    monkeypatch.setattr(gui_app, "STATE_DIR", tmp_path)

    resp = client.get("/api/state/sast_report.json")
    assert resp.status_code == 200
    assert resp.get_json()["summary"]["total"] == 6


def test_scanner_state_files_absent_is_404(client, monkeypatch, tmp_path):
    """Scanner panels must degrade silently before the first scan runs."""
    import gui.app as gui_app

    # Isolate from the real state/ directory so leftover files from a local run
    # cannot make this assertion pass or fail.
    monkeypatch.setattr(gui_app, "STATE_DIR", tmp_path)

    resp = client.get("/api/state/dast_report.json")
    assert resp.status_code == 404


def test_dashboard_exposes_phase5_revalidation_section(client):
    body = client.get("/").get_data(as_text=True)
    assert "Phase 5 — Patched-Target Re-Verification" in body


def test_phase5_state_files_are_allow_listed(client, monkeypatch, tmp_path):
    """The re-exploit results must be viewable but still allow-listed."""
    import gui.app as gui_app

    (tmp_path / "revalidation_report.json").write_text(
        '{"summary": {"total": 6, "confirmed": 0, "partial": 0, "failed": 6}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(gui_app, "STATE_DIR", tmp_path)

    resp = client.get("/api/state/revalidation_report.json")
    assert resp.status_code == 200
    assert resp.get_json()["summary"]["confirmed"] == 0

    assert "reexploit_results.json" in gui_app.ALLOWED_STATE_FILES


def test_state_endpoint_handles_partial_write(client, monkeypatch, tmp_path):
    """Polling during an agent's write must not raise a 500."""
    import gui.app as gui_app

    (tmp_path / "recon_results.json").write_text('{"status": "com', encoding="utf-8")
    monkeypatch.setattr(gui_app, "STATE_DIR", tmp_path)

    resp = client.get("/api/state/recon_results.json")
    assert resp.status_code == 409
    assert "rewritten" in resp.get_json()["error"]


def test_report_page_404_when_missing(client, monkeypatch, tmp_path):
    import gui.app as gui_app
    monkeypatch.setattr(gui_app, "STATE_DIR", tmp_path)
    resp = client.get("/report")
    assert resp.status_code == 404
    assert "Report Not Ready" in resp.get_data(as_text=True)


# ── Markdown renderer ─────────────────────────────────────────────────────────

def test_markdown_renders_headings_tables_and_bold():
    md = "# Title\n\n## Section\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n- item one\n\n**bold** and `code`"
    html = markdown_to_html(md)
    assert "<h1>Title</h1>" in html
    assert "<h2>Section</h2>" in html
    assert "<table class=\"md-table\">" in html
    assert "<th>A</th>" in html and "<td>2</td>" in html
    assert "<li>item one</li>" in html
    assert "<strong>bold</strong>" in html
    assert "<code>code</code>" in html


def test_markdown_escapes_html():
    html = markdown_to_html("<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ── Phase roll-up ─────────────────────────────────────────────────────────────

def test_phase_detection_marks_completed_and_active():
    log = "Phase 1: Reconnaissance\nPhase 2: Exploitation\nPhase 3: Validation\n"
    phases = PipelineRunner._detect_phases(log)
    states = {p["num"]: p["state"] for p in phases}
    assert states[1] == "done"
    assert states[2] == "done"
    assert states[3] == "active"
    assert states[4] == "pending"


def test_phase_detection_marks_all_done_after_full_completion():
    log = "\n".join(f"Phase {n}: x" for n in range(1, 6)) + "\nPIPELINE COMPLETE\n"
    phases = PipelineRunner._detect_phases(log)
    assert all(p["state"] == "done" for p in phases)


def test_phase_detection_marks_unrun_phases_skipped_after_short_mode():
    """A completed recon-only run should show phases 2-5 as skipped, not pending."""
    log = "Phase 1: Reconnaissance\n"
    states = {p["num"]: p["state"] for p in PipelineRunner._detect_phases(log, finished=True)}
    assert states[1] == "done"
    assert all(states[n] == "skipped" for n in (2, 3, 4, 5))


def test_phase_detection_stays_active_while_running():
    """Without a completion signal the current phase must stay 'active'."""
    log = "Phase 1: Reconnaissance\nPhase 2: Exploitation\n"
    states = {p["num"]: p["state"] for p in PipelineRunner._detect_phases(log)}
    assert states[1] == "done"
    assert states[2] == "active"
    assert states[3] == "pending"


def test_log_shows_completion_detects_finished_run():
    finished = ("[ReconAgent] Setting up...\n[ReconAgent] Completed in 1.00s\n"
                "[ValidatorAgent] Setting up...\n[ValidatorAgent] Completed in 0.50s\n")
    assert PipelineRunner._log_shows_completion(finished) is True


def test_log_shows_completion_is_false_mid_run():
    mid_run = ("[ReconAgent] Setting up...\n[ReconAgent] Completed in 1.00s\n"
               "[ExploitAgent] Setting up...\n")
    assert PipelineRunner._log_shows_completion(mid_run) is False


def test_log_shows_completion_handles_full_pipeline_marker():
    assert PipelineRunner._log_shows_completion("PIPELINE COMPLETE") is True


def test_log_shows_completion_is_false_for_empty_log():
    assert PipelineRunner._log_shows_completion("") is False


def test_phase_detection_marks_interrupted_phase_failed():
    log = "Phase 1: Reconnaissance\nPhase 2: Exploitation\n"
    states = {p["num"]: p["state"]
              for p in PipelineRunner._detect_phases(log, finished=True, failed=True)}
    assert states[1] == "done"
    assert states[2] == "failed"
    assert states[3] == "skipped"
