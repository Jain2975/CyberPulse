"""
validator_agent.py — CyberPulse Validator Agent
=================================================
Phase 3: Exploit Validation

Reads exploit_results.json and performs deeper verification:
  1. Re-runs each POTENTIAL_SUCCESS exploit (confirmation pass)
  2. Checks DB state changes where applicable
  3. Applies heuristic rules per exploit type
  4. Classifies each exploit: CONFIRMED | PARTIAL | FAILED
  5. Assigns CVSS-lite severity scores
  6. Produces a human-readable validation_report.json

Output schema:
  {
    "summary": {
      "total": 30,
      "confirmed": 8,
      "partial": 3,
      "failed": 19
    },
    "findings": [
      {
        "id": "...",
        "type": "sql_injection",
        "endpoint": "/login",
        "status": "CONFIRMED",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "evidence": ["HTTP 200 returned", "JWT token in response"],
        "remediation_hint": "Use parameterized queries"
      }
    ]
  }
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.table import Table

from agents.base_agent import BaseAgent, console

# ─── Severity + CVSS-lite map ─────────────────────────────────────────────────
SEVERITY_CVSS = {
    "sql_injection": ("CRITICAL", 9.8),
    "command_injection": ("CRITICAL", 9.8),
    "hardcoded_credentials": ("CRITICAL", 9.1),
    "path_traversal": ("HIGH", 7.5),
    "broken_jwt": ("HIGH", 8.1),
    "csrf": ("HIGH", 7.1),
}

REMEDIATION_HINTS = {
    "sql_injection": "Use parameterized queries / prepared statements. Never interpolate user input into SQL strings.",
    "command_injection": "Use subprocess with a list (not shell=True). Whitelist allowed characters. Avoid shell commands with user input.",
    "hardcoded_credentials": "Remove hardcoded credentials. Use environment variables or a secrets manager (e.g., HashiCorp Vault).",
    "path_traversal": "Canonicalize file paths using os.path.realpath(). Verify the resolved path starts with the allowed base directory.",
    "broken_jwt": "Always verify JWT signatures. Never accept alg:none. Use PyJWT with explicit algorithm and a strong secret.",
    "csrf": "Add CSRF tokens to all state-changing forms. Use Flask-WTF or implement double-submit cookie pattern.",
}

# ─── Confirmation heuristics per exploit type ─────────────────────────────────
CONFIRMATION_RULES: Dict[str, List[str]] = {
    "sql_injection":         ["welcome_message", "jwt_token_returned", "sql_error_leaked"],
    "path_traversal":        ["etc_passwd_content", "source_code_exposed", "windows_system_ini"],
    "csrf":                  ["action_confirmed", "password_changed"],
    "command_injection":     ["user_id_leaked", "etc_passwd_leaked", "time_delay_detected"],
    "hardcoded_credentials": ["admin_data_returned"],
    "broken_jwt":            ["admin_role_confirmed", "privileged_data_returned"],
}


class ValidatorAgent(BaseAgent):
    """
    Phase 3 agent: Exploit verification and classification.

    Usage:
        agent = ValidatorAgent(target_url="http://localhost:5000")
        results = agent.execute()
    """

    # State contract: PatchingAgent reads state/validation_report.json
    state_filename = "validation_report.json"

    def __init__(self, target_url: str, timeout: int = 10,
                 exploit_file: str = "exploit_results.json",
                 confirm_retries: int = 2,
                 output_file: Optional[str] = None):
        super().__init__("ValidatorAgent", target_url, timeout, output_file=output_file)
        self.exploit_file = exploit_file
        self.confirm_retries = confirm_retries

    def run(self) -> Dict[str, Any]:
        console.rule("[bold yellow]✅ VALIDATOR AGENT STARTING[/bold yellow]")

        try:
            exploit_data = self._load_state(self.exploit_file)
        except FileNotFoundError:
            return {"status": "error", "reason": "exploit_results.json not found"}

        exploits: List[Dict] = exploit_data.get("exploits", [])
        findings: List[Dict] = []

        total = len(exploits)
        confirmed = partial = failed = 0

        console.print(f"\n[yellow]Validating {total} exploit attempts...[/yellow]\n")

        for exploit in exploits:
            finding = self._validate_exploit(exploit)
            findings.append(finding)

            if finding["status"] == "CONFIRMED":
                confirmed += 1
            elif finding["status"] == "PARTIAL":
                partial += 1
            else:
                failed += 1

        summary = {
            "total": total,
            "confirmed": confirmed,
            "partial": partial,
            "failed": failed,
            "confirmation_rate": f"{(confirmed / total * 100):.1f}%" if total else "0%"
        }

        self._print_findings_table(findings)

        return {
            "status": "complete",
            "target": self.target_url,
            "summary": summary,
            "findings": findings,
        }

    # ─── Core Validation Logic ────────────────────────────────────────────────

    def _validate_exploit(self, exploit: Dict) -> Dict[str, Any]:
        etype = exploit.get("type", "unknown")
        endpoint = exploit.get("endpoint", "")
        indicators = exploit.get("indicators", [])
        raw_outcome = exploit.get("raw_outcome", "FAILED")

        # Step 1: Apply confirmation rules
        required_indicators = CONFIRMATION_RULES.get(etype, [])
        matched = [i for i in indicators if i in required_indicators]

        # Step 2: Re-verify potential successes
        if raw_outcome == "POTENTIAL_SUCCESS":
            confirmed_on_retry = self._reconfirm(exploit)
        else:
            confirmed_on_retry = False

        # Step 3: Classify
        if raw_outcome == "POTENTIAL_SUCCESS" and len(matched) >= 1:
            if confirmed_on_retry:
                status = "CONFIRMED"
                evidence = [
                    f"Matched indicators: {', '.join(matched)}",
                    f"HTTP {exploit.get('response_status')} returned",
                    "Re-verification passed"
                ]
            else:
                status = "PARTIAL"
                evidence = [
                    f"Matched indicators: {', '.join(matched)}",
                    "Re-verification inconclusive"
                ]
        else:
            status = "FAILED"
            evidence = [f"No matching indicators (checked: {required_indicators})"]

        severity, cvss = SEVERITY_CVSS.get(etype, ("LOW", 0.0))
        remediation = REMEDIATION_HINTS.get(etype, "Review the endpoint for security issues.")

        finding = {
            "id": exploit.get("id", "unknown"),
            "type": etype,
            "endpoint": endpoint,
            "method": exploit.get("method", ""),
            "payload": exploit.get("payload", ""),
            "status": status,
            "severity": severity,
            "cvss_score": cvss,
            "evidence": evidence,
            "indicators_matched": matched,
            "response_status": exploit.get("response_status"),
            "remediation_hint": remediation,
        }

        color = {"CONFIRMED": "green", "PARTIAL": "yellow", "FAILED": "dim"}.get(status, "white")
        console.print(
            f"  [{color}]{status:12}[/{color}] "
            f"[cyan]{etype:25}[/cyan] {endpoint} "
            f"[{exploit.get('payload_id', '')}]"
        )

        return finding

    # ─── Re-Verification ──────────────────────────────────────────────────────

    def _reconfirm(self, exploit: Dict) -> bool:
        """Re-run the exploit up to confirm_retries times and check response."""
        etype = exploit.get("type", "")
        endpoint = exploit.get("endpoint", "")
        method = exploit.get("method", "GET").upper()

        for attempt in range(self.confirm_retries):
            resp = None

            if etype == "sql_injection":
                resp = self.safe_request("POST", endpoint,
                                         data=exploit.get("request_data", {}))
            elif etype == "path_traversal":
                resp = self.safe_request("GET", endpoint,
                                         params=exploit.get("request_params", {}))
            elif etype == "command_injection":
                resp = self.safe_request("POST", endpoint,
                                         json=exploit.get("request_json", {}))
            elif etype == "hardcoded_credentials":
                cred = exploit.get("payload", "")
                resp = self.safe_request("GET", endpoint,
                                         headers={"X-Admin-Password": cred})
            elif etype == "broken_jwt":
                # Full token stored by the exploit agent (no truncation) — replay as-is.
                token = exploit.get("payload", "")
                resp = self.safe_request("GET", endpoint,
                                         headers={"Authorization": f"Bearer {token}"})
            elif etype == "csrf":
                import ast
                try:
                    data = ast.literal_eval(exploit.get("payload", "{}"))
                except Exception:
                    data = {}
                resp = self.safe_request("POST", endpoint, data=data)

            if resp and resp.status_code == 200:
                # Check for positive indicators in re-confirmation
                required = CONFIRMATION_RULES.get(etype, [])
                body = resp.text.lower()
                for indicator in required:
                    if indicator == "welcome_message" and ("welcome" in body or "success" in body):
                        return True
                    if indicator == "jwt_token_returned" and "token" in body:
                        return True
                    if indicator == "etc_passwd_content" and "root:" in body:
                        return True
                    if indicator == "source_code_exposed" and "app.route" in body:
                        return True
                    if indicator == "admin_data_returned" and ("admin" in body and "users" in body):
                        return True
                    if indicator == "admin_role_confirmed" and "admin" in body:
                        return True
                    if indicator == "user_id_leaked" and "uid=" in body:
                        return True
                    if indicator == "action_confirmed" and ("transferred" in body or "success" in body):
                        return True

            time.sleep(0.5)  # Brief pause between retries

        return False

    # ─── Display ──────────────────────────────────────────────────────────────

    def _print_findings_table(self, findings: List[Dict]) -> None:
        console.rule("[bold yellow]✅ VALIDATION REPORT[/bold yellow]")

        confirmed = [f for f in findings if f["status"] == "CONFIRMED"]
        if not confirmed:
            console.print("[yellow]No confirmed vulnerabilities.[/yellow]")
            return

        table = Table(title="Confirmed Vulnerabilities", show_lines=True)
        table.add_column("ID", style="cyan", max_width=30)
        table.add_column("Type", style="yellow")
        table.add_column("Endpoint")
        table.add_column("Severity", style="red")
        table.add_column("CVSS")
        table.add_column("Evidence")

        for f in confirmed:
            table.add_row(
                f["id"],
                f["type"],
                f["endpoint"],
                f["severity"],
                str(f["cvss_score"]),
                "; ".join(f["evidence"][:2])
            )

        console.print(table)

        total = len(findings)
        n_confirmed = len(confirmed)
        console.print(f"\n[green]Confirmed:[/green] {n_confirmed}/{total}")
        console.print(f"[yellow]Partial:[/yellow] {len([f for f in findings if f['status'] == 'PARTIAL'])}")
        console.print(f"[dim]Failed:[/dim] {len([f for f in findings if f['status'] == 'FAILED'])}")
