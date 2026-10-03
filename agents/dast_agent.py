"""
dast_agent.py — CyberPulse DAST Agent (OWASP ZAP)
=================================================
Phase 1c: Dynamic Application Security Testing

Runs OWASP ZAP against the *running* target and normalizes its alerts into the
CyberPulse finding shape, so dynamic findings can be compared before and after
patching.

Execution model: ZAP is distributed as a Docker image. The agent shells out to
`docker run ... zap-baseline.py` (or zap-full-scan.py), mounting:
  - state/zap/       → /zap/wrk    (reports land here)
  - configs/zap/     → /zap/configs (scan policy: which rules FAIL/WARN/IGNORE)

Container → host networking differs per platform, so the agent rewrites the
target URL automatically:
  - Linux / WSL2 (Docker engine) : --network host  → http://127.0.0.1:5000 works
  - Docker Desktop (Win/macOS)   : rewrite localhost → host.docker.internal

If Docker is unavailable the agent reports {"status": "skipped"} with hints
instead of failing the pipeline.

Output schema (state/dast_report.json):
  {
    "status": "complete",
    "tool": "OWASP ZAP 2.15.0",
    "scan_type": "baseline",
    "target": "http://localhost:5000",
    "container_target": "http://host.docker.internal:5000",
    "summary": {
      "total_alerts": 5,
      "by_risk": {"HIGH": 1, "MEDIUM": 3, "LOW": 1, "INFO": 0},
      "urls": 12
    },
    "findings": [
      {
        "id": "10020:X-Frame-Options Header Not Set",
        "plugin_id": "10020",
        "name": "X-Frame-Options Header Not Set",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "cwe": "CWE-1021",
        "endpoint": "http://localhost:5000/",
        "instances": 3,
        "solution": "..." 
      }
    ],
    "reports": {"json": "state/zap/zap_report_baseline.json", "html": "...", "markdown": "..."}
  }
"""

import json
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.table import Table

from agents.base_agent import BaseAgent, PROJECT_ROOT, console

# ─── Defaults ─────────────────────────────────────────────────────────────────
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DEFAULT_ZAP_CONFIG = "configs/zap/baseline.conf"
ZAP_WORK_DIR = PROJECT_ROOT / "state" / "zap"

# ZAP riskcode → normalized severity
RISK_MAP = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
# ZAP confidence code → label
CONFIDENCE_MAP = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "FALSE_POSITIVE"}

SCAN_SCRIPTS = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py", "api": "zap-api-scan.py"}

# zap-baseline.py exit codes: 0 ok, 1 warnings, 2 failures, >=3 error
ZAP_OK_EXIT_CODES = (0, 1, 2)

class DastAgent(BaseAgent):
    """
    Phase 1c agent: dynamic scanning with OWASP ZAP.

    Usage:
        agent = DastAgent(target_url="http://localhost:5000", scan_type="baseline")
        results = agent.execute()
    """

    # State contract: DAST results (terminal output; GUI/human consume it)
    state_filename = "dast_report.json"

    def __init__(
        self,
        target_url: str,
        timeout: int = 10,
        scan_type: str = "baseline",
        image: str = ZAP_IMAGE,
        config_file: str = DEFAULT_ZAP_CONFIG,
        network_mode: Optional[str] = None,
        spider_minutes: int = 2,
        scan_timeout: int = 1800,
        output_file: Optional[str] = None,
    ):
        super().__init__("DastAgent", target_url, timeout, output_file=output_file)
        self.scan_type = scan_type if scan_type in SCAN_SCRIPTS else "baseline"
        self.image = image
        self.config_file = config_file
        # None → auto-detect: 'host' on Linux/WSL2 (Docker engine), bridge otherwise
        self.network_mode = network_mode
        self.spider_minutes = spider_minutes
        self.scan_timeout = scan_timeout

    def run(self) -> Dict[str, Any]:
        console.rule("[bold blue]🌐 DAST AGENT STARTING (OWASP ZAP)[/bold blue]")

        if self.scan_type == "api":
            return {"status": "skipped",
                    "reason": "api scan type requires an OpenAPI spec; use baseline or full"}

        if shutil.which("docker") is None:
            return self._skipped_report()

        ZAP_WORK_DIR.mkdir(parents=True, exist_ok=True)
        report_name = f"zap_report_{self.scan_type}.json"
        html_name = f"zap_report_{self.scan_type}.html"
        md_name = f"zap_report_{self.scan_type}.md"

        network_mode = self._resolve_network_mode()
        container_target = self._container_target(network_mode)

        console.print(f"[blue]ZAP image:[/blue] {self.image}")
        console.print(f"[blue]Scan type:[/blue] {self.scan_type}")
        console.print(f"[blue]Target:[/blue] {self.target_url} "
                      f"[dim](from container: {container_target}, network: {network_mode or 'bridge'})[/dim]")

        cmd = self._build_command(
            network_mode, container_target, report_name, html_name, md_name
        )

        started = time.time()
        with console.status(f"[blue]ZAP {self.scan_type} scan running (this can take a few minutes)..."):
            rc, stdout, stderr = self._execute(cmd)
        duration = time.time() - started

        report_path = ZAP_WORK_DIR / report_name
        if rc not in ZAP_OK_EXIT_CODES and not report_path.exists():
            detail = (stderr or stdout or "").strip()[-800:]
            self.logger.error(f"ZAP failed (exit {rc}): {detail}")
            return {"status": "error", "reason": f"ZAP exited {rc}", "detail": detail,
                    "command": " ".join(cmd)}

        raw = self._read_report(report_path)
        if raw is None:
            return {"status": "error",
                    "reason": "ZAP produced no readable JSON report",
                    "detail": (stderr or stdout or "")[-600:],
                    "command": " ".join(cmd)}

        findings = [self._normalize(a, site) for site, alerts in self._iter_alerts(raw)
                    for a in alerts]
        findings.sort(key=lambda f: (("HIGH", "MEDIUM", "LOW", "INFO").index(f["severity"]),
                                     -f.get("instances", 0), f["name"]))
        summary = self._summarize(raw, findings)
        self._print_findings_table(findings, summary)

        return {
            "status": "complete",
            "tool": self._tool_version(raw),
            "scan_type": self.scan_type,
            "target": self.target_url,
            "container_target": container_target,
            "network_mode": network_mode or "bridge",
            "duration_s": round(duration, 2),
            "summary": summary,
            "findings": findings,
            "reports": {
                "json": self._rel(report_path) if report_path.exists() else None,
                "html": self._rel(ZAP_WORK_DIR / html_name)
                        if (ZAP_WORK_DIR / html_name).exists() else None,
                "markdown": self._rel(ZAP_WORK_DIR / md_name)
                            if (ZAP_WORK_DIR / md_name).exists() else None,
            },
        }

    # ─── Docker / Networking ──────────────────────────────────────────────────

    def _resolve_network_mode(self) -> Optional[str]:
        """
        'host' only works on a real Linux Docker engine. Docker Desktop on
        Windows/macOS runs containers in a VM, so the host is reached through
        host.docker.internal instead.
        """
        if self.network_mode is not None:
            return None if self.network_mode in ("bridge", "") else self.network_mode
        return "host" if platform.system() == "Linux" else None

    def _container_target(self, network_mode: Optional[str]) -> str:
        """Rewrite localhost so the container can reach the host without host networking."""
        if network_mode == "host":
            return self.target_url
        return re.sub(r"(?i)//(localhost|127\.0\.0\.1)",
                      "//host.docker.internal", self.target_url)

    def _build_command(
        self,
        network_mode: Optional[str],
        container_target: str,
        report_name: str,
        html_name: str,
        md_name: str,
    ) -> List[str]:
        script = SCAN_SCRIPTS[self.scan_type]
        config_abs = Path(self.config_file)
        if not config_abs.is_absolute():
            config_abs = PROJECT_ROOT / config_abs
        configs_dir = config_abs.parent

        cmd = ["docker", "run", "--rm",
               "-v", f"{ZAP_WORK_DIR}:/zap/wrk:rw"]
        if configs_dir.exists():
            cmd += ["-v", f"{configs_dir}:/zap/configs:ro"]
        if network_mode:
            cmd += ["--network", network_mode]

        cmd += [
            self.image,
            script,
            "-t", container_target,
            "-J", report_name,
            "-r", html_name,
            "-w", md_name,
            "-m", str(self.spider_minutes),
            "-I",      # don't fail the run on warnings
            "-s",      # short output
        ]
        if configs_dir.exists():
            cmd += ["-c", f"/zap/configs/{config_abs.name}"]
        return cmd

    def _execute(self, cmd: List[str]) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.scan_timeout,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except FileNotFoundError as e:
            return 127, "", f"docker not found: {e}"
        except subprocess.TimeoutExpired:
            return 124, "", f"ZAP scan timed out after {self.scan_timeout}s"

    # ─── Report Parsing ───────────────────────────────────────────────────────

    @staticmethod
    def _read_report(path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _iter_alerts(raw: Dict[str, Any]):
        """Yield (site, alerts) pairs from ZAP's report shape."""
        sites = raw.get("site") or []
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            yield site, (site.get("alerts") or [])

    def _normalize(self, alert: Dict[str, Any], site: Dict[str, Any]) -> Dict[str, Any]:
        instances = alert.get("instances") or []
        first_uri = instances[0].get("uri") if instances else site.get("@name", "")
        cweid = str(alert.get("cweid") or "").strip()

        return {
            "id": f"{alert.get('pluginid', '?')}:{alert.get('alert', 'unknown')}",
            "plugin_id": str(alert.get("pluginid", "")),
            "name": alert.get("alert", "unknown"),
            "severity": RISK_MAP.get(str(alert.get("riskcode", "0")), "INFO"),
            "confidence": CONFIDENCE_MAP.get(str(alert.get("confidence", "")), None),
            "cwe": f"CWE-{cweid}" if cweid and cweid != "0" else None,
            "endpoint": first_uri,
            "instances": int(alert.get("count") or len(instances) or 0),
            "evidence": self._strip_html((instances[0].get("evidence") or "")) if instances else "",
            "description": self._strip_html(alert.get("desc", ""))[:400],
            "solution": self._strip_html(alert.get("solution", ""))[:400],
            "reference": alert.get("reference", ""),
        }

    @staticmethod
    def _strip_html(text: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()

    def _summarize(self, raw: Dict[str, Any], findings: List[Dict]) -> Dict[str, Any]:
        by_risk = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            by_risk[f["severity"]] = by_risk.get(f["severity"], 0) + 1

        urls = set()
        for site, alerts in self._iter_alerts(raw):
            urls.add(site.get("@name", ""))
            for a in alerts:
                for inst in a.get("instances") or []:
                    if inst.get("uri"):
                        urls.add(inst["uri"])

        return {
            "total_alerts": len(findings),
            "by_risk": by_risk,
            "urls_scanned": len(urls),
            "sites": [site.get("@name", "") for site, _ in self._iter_alerts(raw)],
        }

    def _tool_version(self, raw: Dict[str, Any]) -> str:
        return f"OWASP ZAP {raw.get('@version', 'unknown')}"

    @staticmethod
    def _rel(path: Path) -> str:
        """Repo-relative POSIX path (inside the ZAP container it is a Linux path)."""
        try:
            return path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            return path.as_posix()

    # ─── Skipped Report ───────────────────────────────────────────────────────

    def _skipped_report(self) -> Dict[str, Any]:
        console.print("[yellow]Docker not available on this host — DAST skipped.[/yellow]")
        console.print("[dim]ZAP runs from a container. Install Docker, then:[/dim]")
        console.print("[dim]  docker pull ghcr.io/zaproxy/zaproxy:stable[/dim]")
        console.print("[dim]  (WSL2: install Docker Engine or enable Docker Desktop WSL integration)[/dim]")
        return {
            "status": "skipped",
            "reason": "docker is not available",
            "target": self.target_url,
            "install_hints": [
                "docker pull ghcr.io/zaproxy/zaproxy:stable",
                "curl -fsSL https://get.docker.com | sh   # WSL2 / Ubuntu",
            ],
            "findings": [],
            "summary": {"total_alerts": 0,
                        "by_risk": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        }

    # ─── Display ──────────────────────────────────────────────────────────────

    def _print_findings_table(self, findings: List[Dict], summary: Dict[str, Any]) -> None:
        console.rule("[bold blue]🌐 DAST REPORT (OWASP ZAP)[/bold blue]")
        if not findings:
            console.print("[green]✓ No dynamic alerts — clean scan.[/green]")
            return

        table = Table(title=f"ZAP alerts ({len(findings)})")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Alert", style="cyan", max_width=42)
        table.add_column("CWE", style="yellow")
        table.add_column("Cnt", justify="right")
        table.add_column("Endpoint", max_width=38)

        colors = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for f in findings:
            table.add_row(
                f"[{colors.get(f['severity'], 'white')}]{f['severity']}[/]",
                f["name"],
                f["cwe"] or "—",
                str(f.get("instances", 0)),
                (f.get("endpoint") or "")[:60],
            )
        console.print(table)

        risk = summary.get("by_risk", {})
        console.print(
            f"\n[red]HIGH:[/red] {risk.get('HIGH', 0)}  "
            f"[yellow]MEDIUM:[/yellow] {risk.get('MEDIUM', 0)}  "
            f"[cyan]LOW:[/cyan] {risk.get('LOW', 0)}  "
            f"[dim]urls: {summary.get('urls_scanned', 0)}[/dim]"
        )



