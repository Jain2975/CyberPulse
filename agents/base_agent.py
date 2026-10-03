"""
base_agent.py — CyberPulse Base Agent
======================================
All agents inherit from BaseAgent. Provides:
  - Shared state I/O (read/write JSON to state/)
  - Structured logging (via rich)
  - HTTP session management
  - Lifecycle hooks (setup, run, teardown)
  - Event emission (for orchestrator coordination)
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from rich.console import Console
from rich.logging import RichHandler

# ─── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
STATE_DIR = PROJECT_ROOT / "state"
PAYLOADS_DIR = PROJECT_ROOT / "payloads"

# ─── Console ──────────────────────────────────────────────────────────────────
console = Console()

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)


class BaseAgent(ABC):
    """
    Abstract base class for all CyberPulse agents.

    Subclasses must implement:
        run() → Dict[str, Any]   — execute the agent's core task

    Subclasses may set:
        state_filename           — explicit state/ filename for saved results.
                                   If None, defaults to "<agentname>_results.json".
                                   Use this to honor the documented inter-agent
                                   contract (recon_results.json → exploit_results.json
                                   → validation_report.json → patch_report.json).

    Lifecycle:
        setup() → run() → teardown()
    """

    # Explicit state file name (see AGENT_GUIDE.md "State Files" contract).
    # None → fall back to "<agentname>_results.json".
    state_filename: Optional[str] = None

    def __init__(self, name: str, target_url: str, timeout: int = 10,
                 output_file: Optional[str] = None):
        self.name = name
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        # Per-instance override of the state contract filename. Needed so Phase 5
        # (re-exploit against the patched app) can persist its own results without
        # clobbering the original target's exploit/validation output.
        if output_file:
            self.state_filename = output_file
        self.logger = logging.getLogger(name)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"CyberPulse/{name}/1.0",
            "Accept": "application/json, text/html, */*"
        })
        self._started_at: Optional[float] = None
        self._results: Dict[str, Any] = {}

        # Ensure state directory exists
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def setup(self) -> None:
        """Called before run(). Override to add pre-run logic."""
        self.logger.info(f"[{self.name}] Setting up...")
        self._started_at = time.time()

    def teardown(self) -> None:
        """Called after run(). Override to add cleanup logic."""
        elapsed = time.time() - (self._started_at or time.time())
        self.logger.info(f"[{self.name}] Completed in {elapsed:.2f}s")

    def execute(self) -> Dict[str, Any]:
        """
        Main entry point called by the orchestrator.
        Runs: setup → run → teardown → save state.
        """
        self.setup()
        try:
            results = self.run()
            self._results = results
            self._save_state(results)
            return results
        except Exception as e:
            self.logger.error(f"[{self.name}] FAILED: {e}", exc_info=True)
            error_result = {"status": "error", "agent": self.name, "error": str(e)}
            self._save_state(error_result)
            return error_result
        finally:
            self.teardown()

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Core agent logic. Must be implemented by subclasses.
        Returns a dict that will be saved to state/<agent>_results.json.
        """
        ...

    # ─── State I/O ────────────────────────────────────────────────────────────

    def _state_file(self, filename: str) -> Path:
        return STATE_DIR / filename

    def _save_state(self, data: Dict[str, Any], filename: Optional[str] = None) -> None:
        """Persist results dict to JSON state file."""
        filename = (filename or self.state_filename
                    or f"{self.name.lower().replace(' ', '_')}_results.json")
        filepath = self._state_file(filename)
        data["_meta"] = {
            "agent": self.name,
            "target": self.target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_s": round(time.time() - (self._started_at or time.time()), 2)
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"[{self.name}] State saved → {filepath}")

    def _load_state(self, filename: str) -> Dict[str, Any]:
        """Load a previously saved state file."""
        filepath = self._state_file(filename)
        if not filepath.exists():
            raise FileNotFoundError(f"State file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_payloads(self, payload_file: str) -> list:
        """Load a JSON payload library from payloads/."""
        filepath = PAYLOADS_DIR / payload_file
        if not filepath.exists():
            raise FileNotFoundError(f"Payload file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    # ─── HTTP Helpers ─────────────────────────────────────────────────────────

    def get(self, path: str, **kwargs) -> requests.Response:
        url = f"{self.target_url}{path}"
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        url = f"{self.target_url}{path}"
        return self.session.post(url, timeout=self.timeout, **kwargs)

    def safe_request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """HTTP request that swallows exceptions and returns None on failure."""
        try:
            url = f"{self.target_url}{path}"
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Request failed: {method} {path} — {e}")
            return None

    # ─── Utility ──────────────────────────────────────────────────────────────

    def log_finding(self, level: str, message: str) -> None:
        """Emit a colored finding to console."""
        colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "cyan", "INFO": "white"}
        color = colors.get(level, "white")
        console.print(f"  [{color}][{level}][/{color}] {message}")

    def check_target_alive(self) -> bool:
        """Verify the target is reachable before proceeding."""
        resp = self.safe_request("GET", "/health")
        if resp and resp.status_code == 200:
            self.logger.info(f"[{self.name}] Target is alive at {self.target_url}")
            return True
        self.logger.error(f"[{self.name}] Target unreachable at {self.target_url}")
        return False
