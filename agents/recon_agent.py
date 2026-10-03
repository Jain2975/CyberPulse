"""
recon_agent.py — CyberPulse Recon Agent
=========================================
Phase 1: Reconnaissance

Responsibilities:
  1. Verify target is alive (health check)
  2. Port scan (common web ports via socket)
  3. HTTP endpoint discovery (from known list + crawl)
  4. Technology stack fingerprinting (headers, body analysis)
  5. HTTP response header analysis (security headers audit)
  6. Attack surface cataloging → state/recon_results.json

Output schema:
  {
    "target": "http://...",
    "alive": true,
    "open_ports": [80, 443, 5000],
    "endpoints": [
      {"path": "/login", "methods": ["GET","POST"], "status": 200, ...}
    ],
    "tech_stack": {"server": "Werkzeug", "language": "Python", ...},
    "security_headers": {"X-Frame-Options": "MISSING", ...},
    "attack_vectors": [
      {"endpoint": "/login", "type": "sqli", "method": "POST", "params": ["username","password"]}
    ]
  }
"""

import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from rich.table import Table

from agents.base_agent import BaseAgent, console

# ─── Known endpoints to probe ──────────────────────────────────────────────────
KNOWN_PATHS = [
    "/", "/login", "/logout", "/admin", "/api", "/api/profile",
    "/file", "/transfer", "/change_password", "/ping",
    "/health", "/status", "/debug", "/config", "/env",
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
    "/wp-login.php", "/phpmyadmin", "/console", "/graphql"
]

# ─── Ports to scan ─────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3000, 3306, 4000,
                5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 27017]

# ─── Security headers to audit ─────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
]


class ReconAgent(BaseAgent):
    """
    Phase 1 agent: Passive and active reconnaissance.

    Usage:
        agent = ReconAgent(target_url="http://localhost:5000")
        results = agent.execute()
    """

    # State contract: ExploitAgent reads state/recon_results.json
    state_filename = "recon_results.json"

    def __init__(self, target_url: str, timeout: int = 5, port_scan: bool = True,
                 output_file: Optional[str] = None):
        super().__init__("ReconAgent", target_url, timeout, output_file=output_file)
        self.port_scan_enabled = port_scan
        self._parsed = urlparse(target_url)

    def run(self) -> Dict[str, Any]:
        console.rule("[bold cyan]🔍 RECON AGENT STARTING[/bold cyan]")

        if not self.check_target_alive():
            return {"status": "error", "reason": "Target unreachable"}

        results: Dict[str, Any] = {
            "status": "complete",
            "target": self.target_url,
            "alive": True,
            "open_ports": [],
            "endpoints": [],
            "tech_stack": {},
            "security_headers": {},
            "forms": [],
            "attack_vectors": [],
        }

        # ── Step 1: Port scan ─────────────────────────────────────────────────
        if self.port_scan_enabled:
            console.print("\n[bold]Step 1: Port Scan[/bold]")
            results["open_ports"] = self._port_scan()

        # ── Step 2: Endpoint discovery ────────────────────────────────────────
        console.print("\n[bold]Step 2: Endpoint Discovery[/bold]")
        results["endpoints"] = self._discover_endpoints()

        # ── Step 3: Tech stack fingerprinting ─────────────────────────────────
        console.print("\n[bold]Step 3: Tech Stack Fingerprinting[/bold]")
        results["tech_stack"] = self._fingerprint_stack()

        # ── Step 4: Security header audit ─────────────────────────────────────
        console.print("\n[bold]Step 4: Security Header Audit[/bold]")
        results["security_headers"] = self._audit_headers()

        # ── Step 5: Form extraction ───────────────────────────────────────────
        console.print("\n[bold]Step 5: Form Extraction[/bold]")
        results["forms"] = self._extract_forms(results["endpoints"])

        # ── Step 6: Attack surface catalog ────────────────────────────────────
        console.print("\n[bold]Step 6: Cataloging Attack Vectors[/bold]")
        results["attack_vectors"] = self._catalog_attack_vectors(
            results["endpoints"], results["forms"]
        )

        # ── Display summary table ─────────────────────────────────────────────
        self._print_summary(results)

        return results

    # ─── Port Scan ────────────────────────────────────────────────────────────

    def _port_scan(self) -> List[int]:
        host = self._parsed.hostname or "localhost"
        open_ports = []
        self.logger.info(f"Scanning {len(COMMON_PORTS)} ports on {host}...")

        for port in COMMON_PORTS:
            try:
                with socket.create_connection((host, port), timeout=1):
                    open_ports.append(port)
                    self.log_finding("INFO", f"Port {port} OPEN")
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        self.logger.info(f"Open ports: {open_ports}")
        return open_ports

    # ─── Endpoint Discovery ───────────────────────────────────────────────────

    def _discover_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []

        for path in KNOWN_PATHS:
            resp = self.safe_request("GET", path)
            if resp is None:
                continue

            endpoint_info = {
                "path": path,
                "status": resp.status_code,
                "methods": ["GET"],
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": len(resp.content),
                "redirect": resp.url if resp.url != f"{self.target_url}{path}" else None,
                "body_preview": resp.text[:200] if resp.text else "",
            }

            # Check POST support
            post_resp = self.safe_request("POST", path,
                                          data={"_probe": "1"},
                                          allow_redirects=False)
            # NOTE: requests.Response is falsy for any non-2xx status, so a plain
            # `if post_resp` would treat a 401/403 (endpoint exists, POST refused)
            # as "no response" and never record POST support. Compare against None.
            if post_resp is not None and post_resp.status_code not in [404, 405]:
                endpoint_info["methods"].append("POST")

            # Only include non-404 endpoints
            if resp.status_code != 404:
                endpoints.append(endpoint_info)
                status_color = "green" if resp.status_code == 200 else "yellow"
                console.print(
                    f"  [{status_color}]{resp.status_code}[/{status_color}] "
                    f"{path} [{', '.join(endpoint_info['methods'])}]"
                )

        return endpoints

    # ─── Tech Stack Fingerprinting ────────────────────────────────────────────

    def _fingerprint_stack(self) -> Dict[str, Any]:
        resp = self.safe_request("GET", "/")
        if not resp:
            return {}

        stack: Dict[str, Any] = {}

        # Server header
        server = resp.headers.get("Server", "")
        if server:
            stack["server"] = server
            if "werkzeug" in server.lower() or "flask" in server.lower():
                stack["framework"] = "Flask (Python)"
                stack["language"] = "Python"

        # X-Powered-By header
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            stack["powered_by"] = powered

        # Body analysis
        body = resp.text.lower()
        if "flask" in body or "werkzeug" in body:
            stack["framework"] = stack.get("framework", "Flask (Python)")
        if "express" in body or "node" in body:
            stack["framework"] = "Express (Node.js)"
        if "django" in body:
            stack["framework"] = "Django (Python)"
        if "sqlite" in body:
            stack["database"] = "SQLite"

        # Try /health for more info
        health_resp = self.safe_request("GET", "/health")
        if health_resp and health_resp.status_code == 200:
            try:
                health_data = health_resp.json()
                stack["health_info"] = health_data
            except Exception:
                pass

        # Check for debug mode (Flask debug shows tracebacks)
        probe_resp = self.safe_request("GET", "/__non_existent_endpoint__")
        if probe_resp and "Traceback" in probe_resp.text:
            stack["debug_mode"] = True
            self.log_finding("HIGH", "Flask DEBUG MODE is enabled (exposes tracebacks)")
        else:
            stack["debug_mode"] = False

        self.logger.info(f"Tech stack: {stack}")
        return stack

    # ─── Security Header Audit ────────────────────────────────────────────────

    def _audit_headers(self) -> Dict[str, str]:
        resp = self.safe_request("GET", "/")
        if not resp:
            return {}

        audit: Dict[str, str] = {}
        for header in SECURITY_HEADERS:
            value = resp.headers.get(header, "MISSING")
            audit[header] = value
            if value == "MISSING":
                self.log_finding("MEDIUM", f"Missing security header: {header}")
            else:
                self.log_finding("INFO", f"Header present: {header}: {value[:60]}")

        return audit

    # ─── Form Extraction ──────────────────────────────────────────────────────

    def _extract_forms(self, endpoints: List[Dict]) -> List[Dict]:
        forms = []
        for ep in endpoints:
            if "text/html" not in ep.get("content_type", ""):
                continue
            resp = self.safe_request("GET", ep["path"])
            if not resp:
                continue
            soup = BeautifulSoup(resp.text, "lxml")
            for form in soup.find_all("form"):
                form_data = {
                    "endpoint": ep["path"],
                    "action": form.get("action", ep["path"]),
                    "method": form.get("method", "GET").upper(),
                    "fields": [],
                    "has_csrf_token": False,
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if name:
                        form_data["fields"].append({"name": name, "type": itype})
                        if "csrf" in name.lower() or "token" in name.lower():
                            form_data["has_csrf_token"] = True

                if not form_data["has_csrf_token"] and form_data["method"] == "POST":
                    self.log_finding("HIGH",
                                     f"Form at {ep['path']} has no CSRF token (method: POST)")

                forms.append(form_data)

        return forms

    # ─── Attack Vector Catalog ────────────────────────────────────────────────

    def _catalog_attack_vectors(
        self, endpoints: List[Dict], forms: List[Dict]
    ) -> List[Dict]:
        vectors = []

        for ep in endpoints:
            path = ep["path"]
            methods = ep.get("methods", ["GET"])

            # SQL Injection candidates
            if "/login" in path and "POST" in methods:
                vectors.append({
                    "id": "sqli_login",
                    "endpoint": path,
                    "type": "sql_injection",
                    "method": "POST",
                    "params": ["username", "password"],
                    "severity": "CRITICAL",
                    "rationale": "Login form likely uses username in raw SQL query"
                })

            # Path Traversal candidates
            if "/file" in path:
                vectors.append({
                    "id": "pt_file",
                    "endpoint": path,
                    "type": "path_traversal",
                    "method": "GET",
                    "params": ["name"],
                    "severity": "HIGH",
                    "rationale": "File endpoint takes 'name' param — no sanitization likely"
                })

            # Command Injection candidates
            if "/ping" in path and "POST" in methods:
                vectors.append({
                    "id": "cmdi_ping",
                    "endpoint": path,
                    "type": "command_injection",
                    "method": "POST",
                    "params": ["host"],
                    "severity": "CRITICAL",
                    "rationale": "Ping endpoint passes user input to shell command"
                })

            # Admin hardcoded credentials
            if "/admin" in path:
                vectors.append({
                    "id": "hc_admin",
                    "endpoint": path,
                    "type": "hardcoded_credentials",
                    "method": "GET",
                    "params": ["X-Admin-Password (header)"],
                    "severity": "CRITICAL",
                    "rationale": "Admin endpoint likely uses hardcoded password in source"
                })

            # JWT auth endpoint
            if "/api/profile" in path or "/api/" in path:
                vectors.append({
                    "id": "jwt_profile",
                    "endpoint": path,
                    "type": "broken_jwt",
                    "method": "GET",
                    "params": ["Authorization (header)"],
                    "severity": "HIGH",
                    "rationale": "JWT endpoint may accept alg:none unsigned tokens"
                })

        # CSRF vectors from forms without tokens
        for form in forms:
            if not form.get("has_csrf_token") and form.get("method") == "POST":
                vectors.append({
                    "id": f"csrf_{form['endpoint'].strip('/').replace('/', '_')}",
                    "endpoint": form["action"] or form["endpoint"],
                    "type": "csrf",
                    "method": "POST",
                    "params": [f["name"] for f in form.get("fields", [])],
                    "severity": "HIGH",
                    "rationale": "POST form without CSRF token is vulnerable to cross-site forgery"
                })

        self.logger.info(f"Cataloged {len(vectors)} attack vectors")
        return vectors

    # ─── Summary Table ────────────────────────────────────────────────────────

    def _print_summary(self, results: Dict) -> None:
        console.rule("[bold cyan]🔍 RECON SUMMARY[/bold cyan]")

        table = Table(title="Attack Vectors Found", show_lines=True)
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Endpoint")
        table.add_column("Severity", style="red")

        for v in results.get("attack_vectors", []):
            table.add_row(v["id"], v["type"], v["endpoint"], v["severity"])

        console.print(table)
        console.print(f"\n[green]✓ Endpoints found:[/green] {len(results['endpoints'])}")
        console.print(f"[green]✓ Attack vectors:[/green] {len(results['attack_vectors'])}")
        console.print(f"[green]✓ Open ports:[/green] {results['open_ports']}")
