"""
gui/app.py — CyberPulse Web Dashboard
=====================================
A local-only Flask dashboard that shows the swarm in the browser so it can be
demoed to an audience.

IMPORTANT — the terminal experience is unchanged:
  * The orchestrator (main.py) is executed as a subprocess, so every Rich panel,
    colored table and log line still prints in the terminal that launched the GUI.
  * The exact same output is tee'd into state/pipeline.log and streamed live to
    the browser console panel.

Usage:
    python gui/app.py                    # http://127.0.0.1:5002
    python gui/app.py --port 8080
    python main.py --gui                 # same thing, via the orchestrator

Endpoints:
    GET  /                  → dashboard
    GET  /report            → final report (rendered markdown)
    GET  /api/health        → liveness probe
    GET  /api/status        → runner status + phase roll-up
    POST /api/run           → start a pipeline run
    POST /api/stop          → stop the running pipeline (kills child tree)
    GET  /api/log?offset=N  → incremental log lines for live streaming
    GET  /api/state/<file>  → raw agent state JSON
    GET  /api/report        → raw markdown of state/final_report.md

⚠️  FOR ISOLATED SANDBOX / EDUCATIONAL USE ONLY. Binds to localhost by default.
"""

import argparse
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request

PROJECT_ROOT = Path(__file__).parent.parent
STATE_DIR = PROJECT_ROOT / "state"
LOG_PATH = STATE_DIR / "pipeline.log"

# Only these state files may be read through the API (prevents path traversal).
ALLOWED_STATE_FILES = {
    "recon_results.json",
    "exploit_results.json",
    "validation_report.json",
    "patch_report.json",
    # Phase 5 (against the patched app) — kept separate from the originals
    "reexploit_results.json",
    "revalidation_report.json",
    # SAST (Semgrep) and DAST (OWASP ZAP), before and after patching
    "sast_report.json",
    "sast_report_patched.json",
    "dast_report.json",
    "dast_report_patched.json",
}

VALID_MODES = ["full", "recon-only", "exploit-only", "patch-only", "re-exploit"]

PHASE_LABELS = {
    1: "Recon",
    2: "Exploit",
    3: "Validate",
    4: "Patch",
    5: "Re-Exploit",
}

# ─── Pipeline Runner ──────────────────────────────────────────────────────────

class PipelineRunner:
    """
    Runs `python main.py ...` as a subprocess and streams its output.

    Output goes to three places at once:
      1. the terminal that launched the GUI (so the CLI demo is preserved)
      2. state/pipeline.log (durable record, also what the browser reads)
      3. the browser, via GET /api/log?offset=N polling
    """

    def __init__(self, project_root: Path = PROJECT_ROOT, log_path: Path = LOG_PATH):
        self.project_root = project_root
        self.log_path = log_path
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._state: Dict[str, Any] = {
            "running": False,
            "mode": None,
            "target": None,
            "patched_target": None,
            "started_at": None,
            "finished_at": None,
            "duration_s": None,
            "exit_code": None,
            "command": None,
            "_started_monotonic": None,
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Current runner state plus the phase roll-up parsed from the log."""
        with self._lock:
            state = {k: v for k, v in self._state.items() if not k.startswith("_")}

        log_text = self.read_log_text()
        finished = not state["running"] and state["exit_code"] is not None
        failed = finished and state["exit_code"] not in (0, None)

        # After a dashboard restart the in-memory run record is gone, so fall back
        # to the persisted log to decide whether the last run is over.
        if not finished and self._log_shows_completion(log_text):
            finished = True
            failed = False

        state["phases"] = self._detect_phases(log_text, finished=finished, failed=failed)
        state["log_lines"] = log_text.count("\n")
        state["has_report"] = (STATE_DIR / "final_report.md").exists()
        return state

    def validate_request(
        self,
        mode: str,
        target: str,
        patched_target: Optional[str] = None,
    ) -> Optional[str]:
        """Return an error message if the request is invalid, else None."""
        if mode not in VALID_MODES:
            return f"Invalid mode '{mode}'. Choose one of: {', '.join(VALID_MODES)}"
        if mode == "re-exploit" and not patched_target:
            return "re-exploit mode requires a patched target (e.g. http://localhost:5001)"
        if not target:
            return "Target URL is required."
        return None

    def start(
        self,
        mode: str,
        target: str,
        patched_target: Optional[str] = None,
        timeout: int = 10,
        port_scan: bool = True,
    ) -> Tuple[bool, str]:
        """Launch the orchestrator. Returns (started, message)."""
        error = self.validate_request(mode, target, patched_target)
        if error:
            return False, error

        with self._lock:
            if self._state["running"]:
                return False, "A pipeline run is already in progress."

            cmd: List[str] = [
                sys.executable, str(self.project_root / "main.py"),
                "--target", target, "--mode", mode, "--timeout", str(timeout),
            ]
            if patched_target:
                cmd += ["--patched-target", patched_target]
            if not port_scan:
                cmd += ["--no-port-scan"]

            env = dict(os.environ)
            env.update({"PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"})

            self.log_path.write_text("", encoding="utf-8")
            self._state.update({
                "running": True,
                "mode": mode,
                "target": target,
                "patched_target": patched_target,
                "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": None,
                "duration_s": None,
                "exit_code": None,
                "command": " ".join(cmd[1:]),
                "_started_monotonic": time.time(),
            })

            try:
                self._proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.project_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=env,
                )
            except Exception as e:  # noqa: BLE001
                self._state.update({"running": False, "exit_code": -1})
                return False, f"Failed to launch pipeline: {e}"

            self._thread = threading.Thread(target=self._pump, daemon=True)
            self._thread.start()

        return True, f"Pipeline started ({mode} → {target})."

    def stop(self) -> Tuple[bool, str]:
        """Terminate the running pipeline and any child processes it spawned."""
        with self._lock:
            proc = self._proc
        if not proc or proc.poll() is not None:
            return False, "No pipeline is currently running."

        if os.name == "nt":
            # /T also kills the process tree (smoke-test app servers etc.)
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, check=False)
        else:
            proc.terminate()
        return True, "Stop signal sent."

    def read_log_text(self) -> str:
        if not self.log_path.exists():
            return ""
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def log_lines(self, offset: int = 0) -> Dict[str, Any]:
        lines = self.read_log_text().splitlines()
        offset = max(0, min(offset, len(lines)))
        return {
            "lines": lines[offset:],
            "next_offset": len(lines),
            "total": len(lines),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _pump(self) -> None:
        """Read subprocess output; tee to terminal, log file and browser."""
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        try:
            with open(self.log_path, "a", encoding="utf-8") as log:
                for line in proc.stdout:
                    log.write(line)
                    log.flush()
                    self._echo_terminal(line)
        finally:
            code = proc.wait()
            with self._lock:
                started = self._state.get("_started_monotonic")
                self._state.update({
                    "running": False,
                    "exit_code": code,
                    "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "duration_s": round(time.time() - started, 1) if started else None,
                })

    @staticmethod
    def _echo_terminal(line: str) -> None:
        """Mirror a log line into the launching terminal (never crash on cp1252)."""
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
        except UnicodeEncodeError:
            sys.stdout.write(line.encode("ascii", "replace").decode("ascii"))
            sys.stdout.flush()
        except Exception:  # noqa: BLE001 — a closed terminal must not break the GUI
            pass

    @staticmethod
    def _log_shows_completion(log_text: str) -> bool:
        """
        True when every agent that logged "Setting up..." also logged a completion.

        BaseAgent emits exactly one of each per agent, so equal counts mean the last
        agent finished and the run is over — usable even with no in-memory record.
        """
        if "PIPELINE COMPLETE" in log_text:
            return True
        setups = log_text.count("Setting up...")
        completions = log_text.count("Completed in")
        return setups > 0 and completions >= setups

    @staticmethod
    def _detect_phases(
        log_text: str,
        finished: bool = False,
        failed: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Parse the orchestrator banner lines into a phase roll-up.

        main.py prints "Phase N: <Name>" per stage, so the highest phase seen is
        the one currently running (or the last one that ran). Phases that never
        appeared in a finished run are reported as "skipped" (e.g. recon-only).

        `finished`/`failed` come from the runner: only the full pipeline prints
        "PIPELINE COMPLETE", so short modes must be closed out by the caller.
        """
        seen = {int(m) for m in re.findall(r"Phase (\d+):", log_text)}
        ended = finished or "PIPELINE COMPLETE" in log_text
        complete = "PIPELINE COMPLETE" in log_text or (finished and not failed)

        phases: List[Dict[str, Any]] = []
        for num, label in PHASE_LABELS.items():
            if num not in seen:
                state = "skipped" if ended else "pending"
            elif complete or any(n > num for n in seen):
                state = "done"
            elif failed:
                state = "failed"          # run died while this phase was executing
            else:
                state = "active"
            phases.append({"num": num, "label": label, "state": state})
        return phases


# Module-level runner so both the CLI entry point and tests share one instance
runner = PipelineRunner()


# ─── Markdown → HTML (tiny renderer, no extra dependencies) ───────────────────

def markdown_to_html(text: str) -> str:
    """Render the subset of markdown used by state/final_report.md."""
    out: List[str] = []
    in_table = False
    in_list = False

    def close_blocks() -> None:
        nonlocal in_table, in_list
        if in_table:
            out.append("</tbody></table>")
            in_table = False
        if in_list:
            out.append("</ul>")
            in_list = False

    def inline(s: str) -> str:
        s = html.escape(s, quote=False)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        return s

    for raw in text.splitlines():
        line = raw.rstrip()

        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                continue  # separator row
            if not in_table:
                out.append('<table class="md-table"><tbody>')
                in_table = True
                out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue

        close_blocks()

        if not line.strip():
            continue
        if re.fullmatch(r"-{3,}", line.strip()):
            out.append("<hr>")
        elif line.startswith("### "):
            out.append(f"<h3>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.lstrip().startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(line.lstrip()[2:])}</li>")
        elif re.match(r"^\d+\.\s", line.lstrip()):
            out.append(f"<p class='md-step'>{inline(line.lstrip())}</p>")
        else:
            out.append(f"<p>{inline(line)}</p>")

    close_blocks()
    return "\n".join(out)

# ─── Application Factory ──────────────────────────────────────────────────────

def create_app(pipeline_runner: Optional[PipelineRunner] = None) -> Flask:
    """Build the Flask dashboard app (factory keeps it testable)."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["RUNNER"] = pipeline_runner or runner

    @app.route("/")
    def index():
        return render_template("index.html", modes=VALID_MODES)

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok", "service": "cyberpulse-gui"})

    @app.route("/api/status")
    def api_status():
        return jsonify(app.config["RUNNER"].status())

    @app.route("/api/run", methods=["POST"])
    def api_run():
        payload = request.get_json(silent=True) or request.form
        started, message = app.config["RUNNER"].start(
            mode=payload.get("mode", "full"),
            target=payload.get("target", "http://localhost:5000"),
            patched_target=payload.get("patched_target") or None,
            timeout=int(payload.get("timeout") or 10),
            port_scan=str(payload.get("port_scan", "true")).lower() not in ("false", "0", "off"),
        )
        return jsonify({"started": started, "message": message}), (200 if started else 409)

    @app.route("/api/stop", methods=["POST"])
    def api_stop():
        stopped, message = app.config["RUNNER"].stop()
        return jsonify({"stopped": stopped, "message": message}), (200 if stopped else 409)

    @app.route("/api/log")
    def api_log():
        try:
            offset = int(request.args.get("offset", 0))
        except ValueError:
            offset = 0
        return jsonify(app.config["RUNNER"].log_lines(offset))

    @app.route("/api/state/<path:filename>")
    def api_state(filename: str):
        if filename not in ALLOWED_STATE_FILES:
            return jsonify({"error": "state file not allowed"}), 403
        path = STATE_DIR / filename
        if not path.exists():
            return jsonify({"error": f"{filename} not found yet"}), 404
        try:
            with open(path, "r", encoding="utf-8") as f:
                return jsonify(json.load(f))
        except (json.JSONDecodeError, OSError):
            # An agent may be mid-write; the dashboard polls again shortly.
            return jsonify({"error": f"{filename} is being rewritten"}), 409

    @app.route("/api/report")
    def api_report():
        path = STATE_DIR / "final_report.md"
        if not path.exists():
            return jsonify({"error": "final_report.md not found yet"}), 404
        return jsonify({"markdown": path.read_text(encoding="utf-8")})

    @app.route("/report")
    def report_page():
        path = STATE_DIR / "final_report.md"
        if not path.exists():
            return render_template("report_missing.html"), 404
        rendered = markdown_to_html(path.read_text(encoding="utf-8"))
        return render_template("report.html", report_html=rendered)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberPulse Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5002, help="Bind port (default: 5002)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    app = create_app()

    print("=" * 74)
    print("  CyberPulse Web Dashboard")
    print(f"  → http://{args.host}:{args.port}")
    print("  Terminal output from the CLI pipeline is preserved and mirrored here.")
    print("  ⚠️  FOR ISOLATED SANDBOX / EDUCATIONAL USE ONLY")
    print("=" * 74)

    # use_reloader=False so the pipeline subprocess is not started twice
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()



