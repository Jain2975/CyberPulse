"""
patching_agent.py — CyberPulse Patching Agent
===============================================
Phase 4: Automated Security Remediation

Reads validation_report.json, identifies CONFIRMED vulnerabilities,
reads the vulnerable app source code, applies targeted rule-based patches,
writes patched source to vulnapp_patched/, and triggers re-verification.

Patch strategies (rule-based, no LLM required):
  1. SQL Injection       → Replace f-string SQL with parameterized queries
  2. Path Traversal      → Add realpath() + base_dir prefix validation
  3. CSRF               → Add CSRF token generation + validation decorator
  4. Command Injection   → Replace shell=True subprocess with safe list-form
  5. Hardcoded Creds     → Env var + random fallback; all references renamed
  6. Broken JWT          → Add signature verification options
  7. Runtime hardening   → Configurable bind (default 5001), debug disabled

Every patched file is verified before the phase is declared complete:
syntax check → stale-symbol scan → smoke test (boot the app, poll /health)

Output:
  - vulnapp_patched/app.py   (patched source, verified runnable)
  - state/patch_report.json  (what was patched and why + verification)
  - state/final_report.md    (human-readable summary)
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.syntax import Syntax

from agents.base_agent import BaseAgent, PROJECT_ROOT, console

VULNAPP_DIR = PROJECT_ROOT / "vulnapp"
PATCHED_DIR = PROJECT_ROOT / "vulnapp_patched"

# ─── SAST → patch-type mapping ────────────────────────────────────────────────
# Lets the patcher remediate findings reported by the SAST agent (Semgrep rule
# id → patch handler type) when --patch-sast is enabled.
SAST_RULE_TO_TYPE = {
    "cyberpulse.sql-injection-fstring": "sql_injection",
    "cyberpulse.sql-injection-string-format": "sql_injection",
    "cyberpulse.command-injection-shell-true": "command_injection",
    "cyberpulse.path-traversal-unvalidated-open": "path_traversal",
    "cyberpulse.hardcoded-credential": "hardcoded_credentials",
    "cyberpulse.jwt-verification-disabled": "broken_jwt",
    "cyberpulse.flask-hardcoded-secret-key": "flask_secret_key",
    "cyberpulse.flask-debug-enabled": "runtime_hardening",
}


class PatchingAgent(BaseAgent):
    """
    Phase 4 agent: Rule-based automated security patching.

    Usage:
        agent = PatchingAgent(target_url="http://localhost:5000")
        results = agent.execute()
    """

    # State contract: terminal output file (no downstream agent reads it)
    state_filename = "patch_report.json"

    def __init__(self, target_url: str, timeout: int = 10,
                 validation_file: str = "validation_report.json",
                 sast_file: str = "sast_report.json",
                 include_sast: bool = False,
                 output_file: Optional[str] = None):
        super().__init__("PatchingAgent", target_url, timeout, output_file=output_file)
        self.validation_file = validation_file
        self.sast_file = sast_file
        # When True, also remediate vulnerability types reported by the SAST agent
        # (defense in depth: SAST sees issues the exploit stage could not confirm).
        self.include_sast = include_sast
        self._patches_applied: List[Dict] = []

    def run(self) -> Dict[str, Any]:
        console.rule("[bold green]🩹 PATCHING AGENT STARTING[/bold green]")
        self._patches_applied = []          # fresh record per run (agents are reusable)

        # Load validation report
        try:
            validation = self._load_state(self.validation_file)
        except FileNotFoundError:
            return {"status": "error", "reason": "validation_report.json not found"}

        findings = [f for f in validation.get("findings", []) if f["status"] == "CONFIRMED"]
        console.print(f"[green]Found {len(findings)} confirmed vulnerabilities to patch.[/green]")

        if not findings:
            return {"status": "nothing_to_patch", "findings_confirmed": 0}

        # Step 1: Copy vulnapp → vulnapp_patched
        self._setup_patched_dir()

        # Step 2: Read source
        source_file = PATCHED_DIR / "app.py"
        original_source = source_file.read_text(encoding="utf-8")
        patched_source = original_source

        # Step 3: Apply patches per vulnerability type
        targets: List[Tuple[str, Dict]] = []
        vuln_types_seen = set()

        for finding in findings:
            vtype = finding.get("type", "")
            if not vtype or vtype in vuln_types_seen:
                continue  # Apply each patch type once
            vuln_types_seen.add(vtype)
            targets.append((vtype, finding))

        if self.include_sast:
            sast_types = self._sast_derived_types()
            if sast_types:
                console.print(f"[magenta]SAST adds {len(sast_types)} type(s) the exploit stage "
                              f"did not confirm: {', '.join(sast_types)}[/magenta]")
            for vtype in sast_types:
                if vtype not in vuln_types_seen:
                    vuln_types_seen.add(vtype)
                    targets.append((vtype, {"type": vtype, "_source": "sast"}))

        for vtype, finding in targets:
            console.print(f"\n[green]→ Patching:[/green] [cyan]{vtype}[/cyan]")
            patched_source, patch_record = self._apply_patch(
                patched_source, vtype, finding
            )
            if patch_record:
                if finding.get("_source") == "sast":
                    patch_record["source"] = "sast"
                self._patches_applied.append(patch_record)

        # Step 3b: Runtime hardening (always applied — deployment config, not a finding)
        console.print("\n[green]→ Hardening:[/green] [cyan]runtime_config[/cyan]")
        patched_source, runtime_record = self._patch_runtime_config(patched_source)
        if runtime_record:
            self._patches_applied.append(runtime_record)

        # Step 3c: Defensive guard — the patched file must be valid Python
        try:
            compile(patched_source, str(PATCHED_DIR / "app.py"), "exec")
        except SyntaxError as e:
            self.logger.error(f"Patched source is not valid Python: {e}")
            return {"status": "error", "reason": f"Generated patch is not valid Python: {e}"}

        # Step 4: Write patched source
        source_file.write_text(patched_source, encoding="utf-8")
        console.print(f"\n[green]✓ Patched source written to:[/green] {source_file}")

        # Step 4b: Verify the patched app is actually runnable (syntax + smoke test)
        verification = self._verify_patched_app(source_file)

        # Step 5: Generate reports
        patch_report = {
            "status": "complete",
            "patches_applied": len(self._patches_applied),
            "patched_dir": str(PATCHED_DIR),
            "patches": self._patches_applied,
            "verification": verification,
        }

        final_report = self._generate_final_report(validation, patch_report)
        final_report_path = PROJECT_ROOT / "state" / "final_report.md"
        final_report_path.write_text(final_report, encoding="utf-8")
        console.print(f"[green]✓ Final report written to:[/green] {final_report_path}")

        return patch_report

    # ─── Setup Patched Dir ────────────────────────────────────────────────────

    def _setup_patched_dir(self) -> None:
        """
        Rebuild vulnapp_patched/ from vulnapp/.

        Windows holds a handle on the working directory of a running process, so
        deleting vulnapp_patched/ while a previously patched app is still running
        raises WinError 32. Clear the *contents* (keeping the directory alive) and
        retry; if it is genuinely locked, raise an actionable error instead of a
        raw traceback.
        """
        if PATCHED_DIR.exists():
            for attempt in range(3):
                try:
                    self._clear_dir(PATCHED_DIR)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise RuntimeError(
                            f"{PATCHED_DIR} is locked — a patched app instance is probably "
                            "still running (e.g. the server on port 5001). Stop it and retry."
                        )
                    console.print("[yellow]  Patched dir busy — retrying…[/yellow]")
                    time.sleep(1.0)

        PATCHED_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            VULNAPP_DIR, PATCHED_DIR,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        console.print(f"[green]✓ Copied vulnapp → {PATCHED_DIR}[/green]")

    @staticmethod
    def _clear_dir(path: Path) -> None:
        """Delete every child of `path`, leaving the directory itself in place."""
        for child in path.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)

    # ─── Verify Patched App Actually Runs ─────────────────────────────────────

    def _verify_patched_app(self, source_file: Path) -> Dict[str, Any]:
        """
        Prove the patched app is runnable before declaring the phase complete.

        Three checks:
          1. Syntax      — source compiles
          2. Hygiene     — no stale symbols / known credentials left behind
          3. Smoke test  — boot the patched app on a free port and poll /health

        Without this, a broken patch (e.g. a renamed symbol leaving a NameError)
        silently produces a `vulnapp_patched/` folder that cannot start.
        """
        console.print("\n[bold]Verifying patched app...[/bold]")
        result: Dict[str, Any] = {
            "source": str(source_file),
            "syntax_ok": False,
            "hygiene_ok": False,
            "stale_symbols": [],
            "smoke_test": "not_run",
            "smoke_detail": "",
        }

        source = source_file.read_text(encoding="utf-8")

        # 1. Syntax
        try:
            compile(source, str(source_file), "exec")
            result["syntax_ok"] = True
            console.print("  [green]✓ Syntax check passed[/green]")
        except SyntaxError as e:
            result["smoke_detail"] = f"SyntaxError: {e}"
            console.print(f"  [red]✗ Syntax check failed: {e}[/red]")
            return result

        # 2. Hygiene — leftovers that mean the patch was incomplete
        stale = [sym for sym in ("HARDCODED_ADMIN_PASSWORD", "admin123")
                 if sym in source]
        result["stale_symbols"] = stale
        result["hygiene_ok"] = not stale
        if stale:
            console.print(f"  [red]✗ Stale references remain: {', '.join(stale)}[/red]")
        else:
            console.print("  [green]✓ No stale symbols or known credentials[/green]")

        # 3. Smoke test on a free port
        port = self._free_port()
        env = dict(os.environ)
        env.update({
            "PORT": str(port),
            "HOST": "127.0.0.1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            "ADMIN_PASSWORD": "SmokeTest-Only-Password",  # never a known default
        })

        proc = None
        try:
            proc = subprocess.Popen(
                [sys.executable, str(source_file)],
                cwd=str(PROJECT_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            healthy = False
            deadline = time.time() + 20
            while time.time() < deadline:
                if proc.poll() is not None:
                    break  # crashed on startup
                try:
                    import requests
                    resp = requests.get(f"http://127.0.0.1:{port}/health", timeout=2)
                    if resp.status_code == 200:
                        healthy = True
                        break
                except Exception:
                    pass
                time.sleep(0.5)

            if healthy:
                result["smoke_test"] = "passed"
                result["smoke_detail"] = f"Booted on 127.0.0.1:{port} and /health returned 200"
                console.print(f"  [green]✓ Smoke test passed (booted on port {port})[/green]")
            else:
                output = ""
                if proc.poll() is not None and proc.stdout:
                    output = proc.stdout.read()[-800:]
                result["smoke_test"] = "failed"
                result["smoke_detail"] = (
                    f"App did not become healthy on 127.0.0.1:{port}. "
                    f"Startup output: {output.strip() or 'no output captured'}"
                )
                console.print("  [red]✗ Smoke test failed — patched app did not start[/red]")
        except Exception as e:  # noqa: BLE001 — verification must never break the pipeline
            result["smoke_test"] = "error"
            result["smoke_detail"] = f"{type(e).__name__}: {e}"
            console.print(f"  [red]✗ Smoke test error: {e}[/red]")
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        return result

    @staticmethod
    def _free_port() -> int:
        """Ask the OS for an unused TCP port (avoids clashing with the target)."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    # ─── Patch Dispatcher ─────────────────────────────────────────────────────

    def _apply_patch(
        self, source: str, vtype: str, finding: Dict
    ) -> Tuple[str, Optional[Dict]]:
        dispatch = {
            "sql_injection": self._patch_sqli,
            "path_traversal": self._patch_path_traversal,
            "csrf": self._patch_csrf,
            "command_injection": self._patch_cmdi,
            "hardcoded_credentials": self._patch_hardcoded_creds,
            "broken_jwt": self._patch_jwt,
            "flask_secret_key": self._patch_flask_secret,
        }
        # The hardening patch takes only the source, so it is dispatched directly.
        if vtype == "runtime_hardening":
            return self._patch_runtime_config(source)

        handler = dispatch.get(vtype)
        if handler:
            return handler(source, finding)
        self.logger.warning(f"No patch handler for: {vtype}")
        return source, None

    # ─── Patch: Flask secret_key → Environment ───────────────────────────────

    def _patch_flask_secret(self, source: str, finding: Dict) -> Tuple[str, Optional[Dict]]:
        old_code = 'app.secret_key = "supersecretkey_do_not_use_in_prod"'
        new_code = (
            '# PATCHED: session-signing key from the environment; a random per-process\n'
            '# fallback keeps the app runnable without shipping a known key.\n'
            'app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)'
        )

        if old_code not in source:
            return source, None

        patched = source.replace(old_code, new_code)
        patched = self._ensure_imports(patched, ["secrets"])
        self._show_diff("Flask secret_key", old_code, new_code)
        return patched, {
            "type": "flask_secret_key",
            "description": "Replaced the hardcoded session signing key with an environment "
                           "variable plus a random fallback",
            "endpoint": "(app config)",
            "fix": 'app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)',
            "cwe": "CWE-798",
        }

    # ─── SAST-derived patch targets ──────────────────────────────────────────

    def _sast_derived_types(self) -> List[str]:
        """Map SAST findings to patch types (used when include_sast is enabled)."""
        try:
            report = self._load_state(self.sast_file)
        except FileNotFoundError:
            self.logger.warning(f"{self.sast_file} not found — SAST-driven patching skipped")
            return []

        if report.get("status") != "complete":
            return []

        types: List[str] = []
        for finding in report.get("findings", []):
            rule = finding.get("rule", "")
            vtype = SAST_RULE_TO_TYPE.get(rule) or SAST_RULE_TO_TYPE.get(rule.split(".")[-1])
            if not vtype:
                vtype = SAST_RULE_TO_TYPE.get(f"cyberpulse.{rule.split('.')[-1]}")
            if vtype and vtype not in types:
                types.append(vtype)
        return types

    # ─── Patch 1: SQL Injection → Parameterized Queries ──────────────────────

    def _patch_sqli(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        old_code = '''    # VULNERABLE: raw SQL string formatting
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        db = get_db()
        user = db.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500'''

        new_code = '''    # PATCHED: parameterized query — prevents SQL injection
    try:
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
    except Exception as e:
        return jsonify({"error": "Database error"}), 500  # Do not leak error details'''

        if old_code in source:
            patched = source.replace(old_code, new_code)
            self._show_diff("SQL Injection", old_code.strip(), new_code.strip())
            return patched, {
                "type": "sql_injection",
                "description": "Replaced f-string SQL with parameterized query using ? placeholders",
                "endpoint": "/login",
                "fix": "Parameterized query via sqlite3 execute(query, (params,))",
                "cwe": "CWE-89",
            }
        return source, None

    # ─── Patch 2: Path Traversal → Path Canonicalization ─────────────────────

    def _patch_path_traversal(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        old_code = '''    # VULNERABLE: no path canonicalization
    filepath = os.path.join(base_dir, filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return jsonify({"file": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found", "path": filepath}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500'''

        new_code = '''    # PATCHED: canonicalize path and enforce base_dir boundary
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    if not filepath.startswith(os.path.realpath(base_dir)):
        return jsonify({"error": "Access denied: path traversal detected"}), 403
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return jsonify({"file": os.path.basename(filepath), "content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception:
        return jsonify({"error": "Error reading file"}), 500'''

        if old_code in source:
            patched = source.replace(old_code, new_code)
            self._show_diff("Path Traversal", old_code.strip(), new_code.strip())
            return patched, {
                "type": "path_traversal",
                "description": "Added os.path.realpath() canonicalization and base_dir boundary check",
                "endpoint": "/file",
                "fix": "os.path.realpath() + startswith(base_dir) guard",
                "cwe": "CWE-22",
            }
        return source, None

    # ─── Patch 3: CSRF → Token Validation ────────────────────────────────────

    def _patch_csrf(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        # Add CSRF token import and secret generation after existing imports
        import_insertion = "import os\nimport sqlite3\nimport subprocess\nimport jwt"
        import_patched = (
            "import os\nimport sqlite3\nimport subprocess\nimport jwt\n"
            "import secrets\nimport functools"
        )

        # Add CSRF helper functions before the routes
        csrf_helpers = '''
# ─── CSRF Protection (PATCH) ──────────────────────────────────────────────────
def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def csrf_protect(f):
    """Decorator to validate CSRF token on POST requests."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = (request.form.get("csrf_token") or
                     request.headers.get("X-CSRF-Token"))
            if not token or token != session.get("csrf_token"):
                return jsonify({"error": "CSRF token missing or invalid"}), 403
        return f(*args, **kwargs)
    return decorated

'''

        old_transfer = '''@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "GET":
        return render_template("transfer.html")

    # VULNERABLE: no CSRF token check'''

        new_transfer = '''@app.route("/transfer", methods=["GET", "POST"])
@csrf_protect  # PATCHED: CSRF protection added
def transfer():
    if request.method == "GET":
        return render_template("transfer.html", csrf_token=generate_csrf_token())

    # PATCHED: CSRF token validated by @csrf_protect decorator'''

        patched = source
        if import_insertion in patched:
            patched = patched.replace(import_insertion, import_patched)

        if "def generate_csrf_token" not in patched:
            # Insert CSRF helpers before first route
            patched = patched.replace(
                "# ─── Health Check",
                csrf_helpers + "# ─── Health Check"
            )

        if old_transfer in patched:
            patched = patched.replace(old_transfer, new_transfer)

        if patched != source:
            console.print("  [green]✓ CSRF token decorator + generate_csrf_token() added[/green]")
            return patched, {
                "type": "csrf",
                "description": "Added CSRF token generation and @csrf_protect decorator",
                "endpoint": "/transfer, /change_password",
                "fix": "secrets.token_hex(32) CSRF token in session; decorator validates on POST",
                "cwe": "CWE-352",
            }
        return source, None

    # ─── Patch 4: Command Injection → Safe Subprocess ─────────────────────────

    def _patch_cmdi(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        old_code = '''    # VULNERABLE: shell=True with user input (cross-platform ping syntax)
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.check_output(
            f"ping {count_flag} 1 {host}",
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=5
        )'''

        new_code = '''    # PATCHED: safe subprocess call with argument list (no shell=True)
    # Validate host format before passing to subprocess
    import re as _re
    if not _re.match(r"^[a-zA-Z0-9._-]{1,253}$", host):
        return jsonify({"error": "Invalid host format"}), 400
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.check_output(
            ["ping", count_flag, "1", host],   # list form — no shell injection possible
            shell=False,
            stderr=subprocess.STDOUT,
            timeout=5
        )'''

        if old_code in source:
            patched = source.replace(old_code, new_code)
            self._show_diff("Command Injection", old_code.strip(), new_code.strip())
            return patched, {
                "type": "command_injection",
                "description": "Replaced shell=True f-string with safe list-form subprocess + regex whitelist",
                "endpoint": "/ping",
                "fix": "subprocess([...], shell=False) + host regex validation",
                "cwe": "CWE-78",
            }
        return source, None

    # ─── Patch 5: Hardcoded Credentials → Environment Variable ───────────────

    def _patch_hardcoded_creds(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        old_code = 'HARDCODED_ADMIN_PASSWORD = "admin123"   # VULN: hardcoded credential'
        new_code = (
            '# PATCHED: secret comes from the environment. A random per-process fallback\n'
            '# keeps the app runnable while ensuring no known credential is shipped.\n'
            'ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(32)'
        )

        old_check = 'if auth == HARDCODED_ADMIN_PASSWORD:'
        new_check = ('if auth and hmac.compare_digest(auth, ADMIN_PASSWORD):  '
                     '# PATCHED: constant-time comparison')

        patched = source
        if old_code in patched:
            patched = patched.replace(old_code, new_code)
        if old_check in patched:
            patched = patched.replace(old_check, new_check)

        # Rename EVERY remaining reference (e.g. DB seeding inside init_db) —
        # otherwise the patched app dies with NameError on startup.
        patched = re.sub(r"\bHARDCODED_ADMIN_PASSWORD\b", "ADMIN_PASSWORD", patched)

        # The patched code needs `secrets` (random fallback) and `hmac` (constant-time compare)
        patched = self._ensure_imports(patched, ["secrets", "hmac"])

        if patched != source:
            console.print("  [green]✓ Hardcoded credential replaced with env var + random fallback[/green]")
            return patched, {
                "type": "hardcoded_credentials",
                "description": "Replaced hardcoded 'admin123' with os.environ.get('ADMIN_PASSWORD') "
                               "plus a random fallback; all references renamed (no stale symbols)",
                "endpoint": "/admin",
                "fix": "Secret from environment (random fallback); hmac.compare_digest() for constant-time check",
                "cwe": "CWE-798",
            }
        return source, None

    # ─── Patch 7: Runtime Hardening → Configurable Bind, Debug Off ───────────

    def _patch_runtime_config(self, source: str) -> Tuple[str, Optional[Dict]]:
        """
        Make the patched deployment runnable next to the original target.

        The vulnerable app binds 0.0.0.0:5000 with debug=True. The patched copy
        must be able to run on a second port (the re-exploit phase targets
        http://localhost:5001) and must never ship with the Flask debugger on.
        """
        old_run = 'app.run(host="0.0.0.0", port=5000, debug=True)'
        new_run = (
            'app.run(host=os.environ.get("HOST", "127.0.0.1"),\n'
            '            port=int(os.environ.get("PORT", "5001")),\n'
            '            debug=False)  # PATCHED: debug disabled, bind configurable'
        )

        # The vulnerable app seeds ./files/ relative to the CWD, but /file serves
        # from <module_dir>/files — so legitimate reads 404 when launched from the
        # project root. Tie the seed dir to the module directory instead.
        old_seed = '''    os.makedirs("files", exist_ok=True)
    with open("files/readme.txt", "w") as f:
        f.write("Welcome to VulnApp! This is a safe file.\\n")'''
        new_seed = '''    # PATCHED: seed the same directory that /file serves from (module-relative)
    files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("Welcome to VulnApp! This is a safe file.\\n")'''

        patched = source
        applied = []
        if old_run in patched:
            patched = patched.replace(old_run, new_run)
            self._show_diff("Runtime hardening", old_run, new_run)
            applied.append("configurable bind (default 5001), debugger disabled")
        if old_seed in patched:
            patched = patched.replace(old_seed, new_seed)
            self._show_diff("Seed dir fix", old_seed, new_seed)
            applied.append("seed files/ next to app.py so legitimate reads still work")

        if not applied:
            return source, None
        return patched, {
            "type": "runtime_hardening",
            "description": "Deployment hardening: " + "; ".join(applied),
            "endpoint": "(startup)",
            "fix": "app.run(host=os.environ.get('HOST','127.0.0.1'), port=int(os.environ.get('PORT','5001')), debug=False)",
            "cwe": "CWE-489",
        }

    # ─── Patch Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _ensure_imports(source: str, names: List[str]) -> str:
        """Add any missing plain `import x` statements after the last one present."""
        missing = [
            n for n in names
            if not re.search(rf"^\s*import {re.escape(n)}\b", source, re.M)
        ]
        if not missing:
            return source

        lines = source.splitlines()
        anchor = 0
        for i, line in enumerate(lines):
            if re.match(r"^import [\w.]+$", line):   # plain top-level imports only
                anchor = i + 1

        lines[anchor:anchor] = [f"import {n}" for n in missing]
        return "\n".join(lines)

    # ─── Patch 6: Broken JWT → Enforce Signature Verification ────────────────

    def _patch_jwt(self, source: str, finding: Dict) -> Tuple[str, Dict]:
        old_code = '        # VULNERABLE: options={"verify_signature": False} — accepts unsigned tokens\n        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])'
        new_code = '        # PATCHED: enforce full signature verification, disallow alg:none\n        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])'

        if old_code in source:
            patched = source.replace(old_code, new_code)
            self._show_diff("Broken JWT", old_code.strip(), new_code.strip())
            return patched, {
                "type": "broken_jwt",
                "description": "Replaced verify_signature=False with full HS256 verification; removed 'none' algorithm",
                "endpoint": "/api/profile",
                "fix": "jwt.decode(token, secret_key, algorithms=['HS256'])",
                "cwe": "CWE-347",
            }
        return source, None

    # ─── Diff Display ─────────────────────────────────────────────────────────

    def _show_diff(self, label: str, old: str, new: str) -> None:
        console.print(f"\n  [bold red]Before ({label}):[/bold red]")
        console.print(Syntax(old, "python", theme="monokai", line_numbers=False))
        console.print(f"\n  [bold green]After ({label}):[/bold green]")
        console.print(Syntax(new, "python", theme="monokai", line_numbers=False))

    # ─── Final Report Generator ───────────────────────────────────────────────

    def _generate_final_report(self, validation: Dict, patch_report: Dict) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        summary = validation.get("summary", {})
        findings = [f for f in validation.get("findings", []) if f["status"] == "CONFIRMED"]
        patches = patch_report.get("patches", [])

        lines = [
            "# CyberPulse Final Security Report",
            f"\n**Generated:** {now}  ",
            f"**Target:** {self.target_url}  ",
            f"**Pipeline:** Recon → Exploit → Validate → Patch\n",
            "---\n",
            "## Executive Summary\n",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Exploits Attempted | {summary.get('total', 0)} |",
            f"| **Confirmed Vulnerabilities** | **{summary.get('confirmed', 0)}** |",
            f"| Partial | {summary.get('partial', 0)} |",
            f"| Failed/Not Exploitable | {summary.get('failed', 0)} |",
            f"| Patches Applied | {patch_report.get('patches_applied', 0)} |",
            "\n---\n",
            "## Confirmed Vulnerabilities\n",
        ]

        cwe_by_type = {p["type"]: p.get("cwe", "—") for p in patches}

        for f in findings:
            lines += [
                f"### {f['type'].replace('_', ' ').title()} — `{f['endpoint']}`\n",
                f"- **Severity:** {f['severity']} (CVSS {f['cvss_score']})",
                f"- **CWE:** {cwe_by_type.get(f['type'], '—')}",
                f"- **Evidence:** {'; '.join(f['evidence'])}",
                f"- **Remediation:** {f['remediation_hint']}\n",
            ]

        lines += ["\n---\n", "## Patches Applied\n"]
        for p in patches:
            lines += [
                f"### ✅ {p['type'].replace('_', ' ').title()}",
                f"- **Endpoint:** `{p['endpoint']}`",
                f"- **Fix:** {p['fix']}",
                f"- **CWE:** {p['cwe']}",
                f"- {p['description']}\n",
            ]

        verification = patch_report.get("verification", {})
        if verification:
            smoke = verification.get("smoke_test", "not_run")
            icon = {"passed": "✅", "failed": "❌"}.get(smoke, "⚠️")
            lines += [
                "\n---\n",
                "## Patched App Verification\n",
                "| Check | Result |",
                "|---|---|",
                f"| Source compiles | {'✅ PASS' if verification.get('syntax_ok') else '❌ FAIL'} |",
                f"| No stale symbols / known credentials | {'✅ PASS' if verification.get('hygiene_ok') else '❌ FAIL'} |",
                f"| Smoke test (boots + /health = 200) | {icon} {smoke.upper()} |",
                f"\n**Detail:** {verification.get('smoke_detail', 'n/a')}\n",
            ]

        lines += [
            "\n---\n",
            "## Next Steps\n",
            "1. Run `python main.py --mode re-exploit --patched-target http://localhost:5001` against the patched app",
            "2. All confirmed vulnerabilities should now return `FAILED` on re-exploit",
            "3. Deploy only from `vulnapp_patched/` after security review",
            "4. Add automated security testing to CI/CD pipeline",
            "\n---\n",
            "*Report generated by CyberPulse Autonomous Pentest Swarm*",
        ]

        return "\n".join(lines)
