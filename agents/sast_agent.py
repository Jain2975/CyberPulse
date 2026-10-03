"""
sast_agent.py — CyberPulse SAST Agent (Semgrep)
===============================================
Phase 1b: Static Application Security Testing

Scans the target's source code with Semgrep and normalizes the results into the
same shape the rest of the swarm uses, so findings can be compared before and
after patching.

Why a re-scan matters: the PatchingAgent changes source files. Re-running SAST
over `vulnapp_patched/` is static proof that the vulnerable patterns are gone
(independent of whether the exploit still works at runtime).

Tool discovery (in order):
  1. `semgrep` on PATH            → native execution
  2. `docker` on PATH             → semgrep/semgrep container
  3. neither                      → {"status": "skipped"} with install hints

Output schema (state/sast_report.json):
  {
    "status": "complete",
    "tool": "semgrep 1.159.0",
    "scan_paths": ["vulnapp"],
    "summary": {
      "total": 8,
      "by_severity": {"HIGH": 4, "MEDIUM": 3, "LOW": 1, "INFO": 0},
      "files_scanned": 1,
      "rules_triggered": ["cyberpulse.sql-injection-fstring"]
    },
    "findings": [
      {
        "id": "cyberpulse.sql-injection-fstring:vulnapp/app.py:104",
        "rule": "cyberpulse.sql-injection-fstring",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "file": "vulnapp/app.py",
        "line": 104,
        "message": "SQL query built with an f-string ..."
      }
    ]
  }
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.table import Table

from agents.base_agent import BaseAgent, PROJECT_ROOT, console

# ─── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = "configs/semgrep/cyberpulse.yml"
DEFAULT_SCAN_PATH = "vulnapp"
SEMGREP_IMAGE = "semgrep/semgrep:latest"

# Semgrep severity → normalized severity used across CyberPulse
SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

# Exit codes: 0 = no findings, 1 = findings found, anything else = error
SEMGREP_FINDINGS_EXIT = 1

class SastAgent(BaseAgent):
    """
    Phase 1b agent: static analysis with Semgrep.

    Usage:
        agent = SastAgent(scan_paths=["vulnapp"])
        results = agent.execute()
    """

    # State contract: SAST results (terminal output; GUI/human consume it)
    state_filename = "sast_report.json"

    def __init__(
        self,
        target_url: str = "local",
        timeout: int = 10,
        scan_paths: Optional[List[str]] = None,
        config_file: str = DEFAULT_CONFIG,
        rulesets: Optional[List[str]] = None,
        image: str = SEMGREP_IMAGE,
        scan_timeout: int = 300,
        output_file: Optional[str] = None,
    ):
        super().__init__("SastAgent", target_url, timeout, output_file=output_file)
        self.scan_paths = scan_paths or [DEFAULT_SCAN_PATH]
        self.config_file = config_file
        # Extra registry rulesets, e.g. ["p/python", "p/owasp-top-ten"] (needs network)
        self.rulesets = rulesets or []
        self.image = image
        self.scan_timeout = scan_timeout

    def run(self) -> Dict[str, Any]:
        console.rule("[bold magenta]🔎 SAST AGENT STARTING (Semgrep)[/bold magenta]")

        # ── Resolve scan paths ────────────────────────────────────────────────
        paths: List[Path] = []
        for p in self.scan_paths:
            candidate = Path(p)
            if not candidate.is_absolute():
                candidate = PROJECT_ROOT / candidate
            if candidate.exists():
                paths.append(candidate)
            else:
                self.logger.warning(f"Scan path does not exist, skipping: {candidate}")

        if not paths:
            return {"status": "error", "reason": "No valid scan paths found",
                    "scan_paths": self.scan_paths}

        config_path = Path(self.config_file)
        if not config_path.is_absolute():
            config_path = PROJECT_ROOT / config_path
        if not config_path.exists():
            return {"status": "error", "reason": f"Semgrep config not found: {config_path}"}

        # ── Tool discovery ────────────────────────────────────────────────────
        runner = self._detect_runner()
        if runner is None:
            return self._skipped_report(paths)

        console.print(f"[magenta]Semgrep runner:[/magenta] [cyan]{runner}[/cyan]")
        console.print(f"[magenta]Scanning:[/magenta] {', '.join(str(p) for p in paths)}")

        # ── Execute ───────────────────────────────────────────────────────────
        cmd = self._build_command(runner, paths, config_path)
        started = time.time()
        with console.status("[magenta]Semgrep running..."):
            rc, stdout, stderr = self._execute(cmd)
        duration = time.time() - started

        if rc not in (0, SEMGREP_FINDINGS_EXIT):
            detail = (stderr or stdout or "").strip()[-800:]
            self.logger.error(f"Semgrep failed (exit {rc}): {detail}")
            return {"status": "error", "reason": f"semgrep exited {rc}", "detail": detail}

        raw = self._parse_output(stdout, stderr)
        if raw is None:
            return {"status": "error", "reason": "Could not parse Semgrep JSON output",
                    "detail": (stderr or stdout or "")[-500:]}

        # ── Normalize ─────────────────────────────────────────────────────────
        findings = [self._normalize(r) for r in raw.get("results", [])]
        findings.sort(key=lambda f: (("HIGH", "MEDIUM", "LOW", "INFO").index(f["severity"]),
                                     f["file"], f["line"]))
        summary = self._summarize(findings, raw, paths)

        self._print_findings_table(findings, summary)

        return {
            "status": "complete",
            "tool": self._tool_version(raw, runner),
            "runner": runner,
            "config": self._rel(config_path),
            "scan_paths": [self._rel(p) for p in paths],
            "duration_s": round(duration, 2),
            "summary": summary,
            "findings": findings,
        }

    # ─── Tool Discovery & Execution ───────────────────────────────────────────

    @staticmethod
    def _detect_runner() -> Optional[str]:
        """Return 'native', 'docker' or None depending on what is available."""
        if shutil.which("semgrep"):
            return "native"
        if shutil.which("docker"):
            return "docker"
        return None

    def _build_command(self, runner: str, paths: List[Path], config_path: Path) -> List[str]:
        """
        Build the Semgrep invocation.

        Native : semgrep --config <cfg> <paths>
        Docker : mount the repo read-only at /src so the same relative config path
                 resolves inside the container.
        """
        report_file = self._report_tmp_path()
        out_arg = str(report_file) if runner == "native" else self._rel(report_file)

        args = [
            "semgrep",
            "--json",
            "--output", out_arg,
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
        ]
        for cfg in [config_path] + [Path(r) for r in self.rulesets]:
            args += ["--config", self._rel(cfg)]
        for p in paths:
            args.append(self._rel(p))

        if runner == "native":
            return args

        return [
            "docker", "run", "--rm",
            "-v", f"{PROJECT_ROOT}:/src:ro",
            "-w", "/src",
            "-e", "SEMGREP_SEND_METRICS=off",
            self.image,
            *args,
        ]

    @staticmethod
    def _report_tmp_path() -> Path:
        return PROJECT_ROOT / "state" / ".semgrep_tmp.json"

    def _execute(self, cmd: List[str]) -> Tuple[int, str, str]:
        env = dict(os.environ)
        env.update({"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.scan_timeout,
                env=env,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except FileNotFoundError as e:
            return 127, "", f"{cmd[0]} not found: {e}"
        except subprocess.TimeoutExpired:
            return 124, "", f"Semgrep timed out after {self.scan_timeout}s"

    def _parse_output(self, stdout: str, stderr: str) -> Optional[Dict[str, Any]]:
        """
        Read the JSON report.

        Semgrep writes to --output; stdout is parsed as a fallback so a different
        invocation style still works.
        """
        report_file = self._report_tmp_path()
        if report_file.exists():
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                report_file.unlink(missing_ok=True)
                return data
            except (json.JSONDecodeError, OSError):
                report_file.unlink(missing_ok=True)

        for text in (stdout, stderr):
            if not text:
                continue
            stripped = text.strip()
            start = stripped.find("{")
            if start == -1:
                continue
            try:
                return json.loads(stripped[start:])
            except json.JSONDecodeError:
                continue
        return None

    # ─── Normalization ────────────────────────────────────────────────────────

    def _normalize(self, result: Dict[str, Any]) -> Dict[str, Any]:
        check_id = result.get("check_id", "unknown")
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        path = self._rel(Path(result.get("path", "?")))
        line = (result.get("start") or {}).get("line", 0)

        return {
            "id": f"{check_id}:{path}:{line}",
            "rule": check_id,
            "severity": SEVERITY_MAP.get(str(extra.get("severity", "INFO")).upper(), "INFO"),
            "cwe": self._first_cwe(metadata.get("cwe")),
            "owasp": self._first(metadata.get("owasp")),
            "file": path,
            "line": line,
            "message": (extra.get("message") or "").strip().replace("\n", " "),
            "confidence": (str(metadata.get("confidence", "")).upper() or None),
        }

    @staticmethod
    def _first(value: Any) -> Optional[str]:
        if isinstance(value, (list, tuple)):
            return str(value[0]) if value else None
        return str(value) if value else None

    @classmethod
    def _first_cwe(cls, value: Any) -> Optional[str]:
        """Semgrep metadata may be ['CWE-89: ...'] → keep just the identifier."""
        raw = cls._first(value)
        if not raw:
            return None
        m = re.search(r"CWE-\d+", raw, re.IGNORECASE)
        return m.group(0).upper() if m else raw

    def _summarize(self, findings: List[Dict], raw: Dict, paths: List[Path]) -> Dict[str, Any]:
        by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        files_with_findings = {(r.get("path") or "") for r in raw.get("results", [])}
        scanned = (raw.get("paths") or {}).get("scanned") or []
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "files_scanned": len(scanned) if scanned else len(files_with_findings),
            "files_with_findings": len(files_with_findings),
            "rules_triggered": sorted({f["rule"] for f in findings}),
            "errors": len(raw.get("errors", []) or []),
        }

    def _tool_version(self, raw: Dict[str, Any], runner: str) -> str:
        meta = raw.get("_meta") or {}
        version = str(meta.get("semgrep_version") or meta.get("version") or "").strip()
        if not version:
            version = self._native_version() if runner == "native" else "unknown"
        return f"semgrep {version}".strip()

    @staticmethod
    def _native_version() -> str:
        try:
            proc = subprocess.run(["semgrep", "--version"], capture_output=True,
                                  text=True, timeout=60)
            for line in (proc.stdout or proc.stderr or "").splitlines():
                line = line.strip()
                if line and line[0].isdigit():
                    return line
        except Exception:  # noqa: BLE001
            pass
        return "unknown"

    @staticmethod
    def _rel(path: Path) -> str:
        """
        Repo-relative POSIX path.

        Forward slashes matter: these paths are passed into the Semgrep Docker
        container (a Linux filesystem), so Windows-style backslashes would break.
        """
        try:
            return path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            return path.as_posix()

    # ─── Skipped Report ───────────────────────────────────────────────────────

    def _skipped_report(self, paths: List[Path]) -> Dict[str, Any]:
        console.print("[yellow]Semgrep not available on this host — SAST skipped.[/yellow]")
        console.print("[dim]Install one of:[/dim]")
        console.print("[dim]  • pipx install semgrep         (native, recommended in WSL)[/dim]")
        console.print("[dim]  • docker pull semgrep/semgrep (Docker fallback)[/dim]")
        return {
            "status": "skipped",
            "reason": "semgrep and docker are both unavailable",
            "scan_paths": [self._rel(p) for p in paths],
            "install_hints": [
                "pipx install semgrep",
                "pip install semgrep",
                "docker pull semgrep/semgrep:latest",
            ],
            "findings": [],
            "summary": {"total": 0, "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        }

    # ─── Display ──────────────────────────────────────────────────────────────

    def _print_findings_table(self, findings: List[Dict], summary: Dict[str, Any]) -> None:
        console.rule("[bold magenta]🔎 SAST REPORT (Semgrep)[/bold magenta]")
        if not findings:
            console.print("[green]✓ No static findings — clean scan.[/green]")
            return

        table = Table(title=f"Semgrep findings ({len(findings)})")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", style="cyan", max_width=38)
        table.add_column("Location", max_width=34)
        table.add_column("CWE", style="yellow")
        table.add_column("Message", max_width=48)

        colors = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for f in findings:
            table.add_row(
                f"[{colors.get(f['severity'], 'white')}]{f['severity']}[/]",
                f["rule"].split(".")[-1],
                f"{f['file']}:{f['line']}",
                f["cwe"] or "—",
                (f["message"][:90] + "…") if len(f["message"]) > 90 else f["message"],
            )
        console.print(table)

        sev = summary.get("by_severity", {})
        console.print(
            f"\n[red]HIGH:[/red] {sev.get('HIGH', 0)}  "
            f"[yellow]MEDIUM:[/yellow] {sev.get('MEDIUM', 0)}  "
            f"[cyan]LOW:[/cyan] {sev.get('LOW', 0)}  "
            f"[dim]files scanned: {summary.get('files_scanned', 0)}[/dim]"
        )



