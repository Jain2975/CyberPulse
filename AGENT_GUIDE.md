# CyberPulse — Agent Guide
## Autonomous Penetration Testing & Vulnerability Exploitation Swarm

> **⚠️ LEGAL DISCLAIMER**: This system is designed **exclusively** for use against isolated,
> purposefully vulnerable applications in a controlled sandbox environment. Running CyberPulse
> against any system you do not own or have explicit written authorization to test is **illegal**
> under the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, and equivalent laws
> worldwide. The authors accept no liability for misuse.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Agent Roles & Responsibilities](#3-agent-roles--responsibilities)
4. [Shared State Contract](#4-shared-state-contract)
5. [How to Run the Pipeline](#5-how-to-run-the-pipeline)
6. [Agent Development Guide](#6-agent-development-guide)
7. [Payload Library Reference](#7-payload-library-reference)
8. [Target App (VulnApp) Reference](#8-target-app-vulnapp-reference)
9. [Extending CyberPulse](#9-extending-cyberpulse)
10. [Troubleshooting](#10-troubleshooting)
11. [Security Concepts Reference](#11-security-concepts-reference)
12. [Web Dashboard (GUI)](#12-web-dashboard-gui)
13. [SAST & DAST Scanners](#13-sast--dast-scanners)

---

## 1. System Overview

CyberPulse is a **multi-agent swarm** that mimics a professional red-team/blue-team security
engagement cycle — fully automated. It operates in five sequential phases:

```
┌──────────────────────────────────────────────────────────┐
│  Phase 1    Phase 2    Phase 3    Phase 4     Phase 5    │
│  RECON  →  EXPLOIT  →  VALIDATE  →  PATCH  →  RE-EXPLOIT│
│                                                           │
│  Maps the   Fires     Confirms   Fixes the   Verifies   │
│  target    payloads   findings   source      the fix    │
└──────────────────────────────────────────────────────────┘
```

### What Makes This Hard (and Educational)

| Challenge | Why It Matters |
|---|---|
| Multi-step reasoning | Each agent depends on the output of the previous one |
| Dynamic tool execution | Agents run shell commands, make HTTP requests, parse responses |
| Structured + unstructured output | HTTP bodies can be JSON, HTML, plaintext, binary |
| Precise code generation | Patches must not break the app — valid Python is required |
| State management | All agents share a persistent state store (JSON files) |
| False positive filtering | Validator must distinguish real exploits from noise |

---

## 2. Architecture

### High-Level

```
main.py (Orchestrator)
    │
    ├── agents/recon_agent.py      → Phase 1
    ├── agents/sast_agent.py       → Phase 1b  (Semgrep, static)
    ├── agents/exploit_agent.py    → Phase 2
    ├── agents/validator_agent.py  → Phase 3
    ├── agents/dast_agent.py       → Phase 3b  (OWASP ZAP, dynamic)
    ├── agents/patching_agent.py   → Phase 4
    │   └── (re-runs ExploitAgent + ValidatorAgent for Phase 5)
    │
    ├── agents/base_agent.py       → Shared base class
    │
    ├── configs/
    │   ├── semgrep/cyberpulse.yml → SAST rule pack (8 rules)
    │   └── zap/baseline.conf      → DAST scan policy (IGNORE/WARN/FAIL per rule)
    │
    ├── payloads/                  → Attack payload libraries (JSON)
    │   ├── sqli_payloads.json
    │   ├── path_traversal_payloads.json
    │   ├── csrf_payloads.json
    │   ├── cmdi_payloads.json
    │   └── jwt_payloads.json
    │
    ├── state/                     → Shared state store (auto-created)
    │   ├── recon_results.json
    │   ├── exploit_results.json
    │   ├── validation_report.json
    │   ├── patch_report.json
    │   ├── reexploit_results.json      ← Phase 5 (patched target)
    │   ├── revalidation_report.json    ← Phase 5 verdict
    │   ├── sast_report.json            ← Semgrep (original source)
    │   ├── sast_report_patched.json    ← Semgrep (patched source)
    │   ├── dast_report.json            ← ZAP (original target)
    │   ├── dast_report_patched.json    ← ZAP (patched target)
    │   ├── zap/                        ← raw ZAP reports (json/html/md)
    │   ├── pipeline.log               → live run log (written by the GUI runner)
    │   └── final_report.md
    │
    ├── gui/                       → Optional web dashboard (Flask)
    │   ├── app.py                 → dashboard API + pipeline subprocess runner
    │   ├── templates/             → index.html, report.html
    │   └── static/                → dashboard.css, dashboard.js
    │
    ├── vulnapp/                   → Vulnerable target (Flask + SQLite)
    └── vulnapp_patched/           → Patched copy (created + verified by PatchingAgent)
```

### Data Flow

```
vulnapp (running) ──HTTP──▶ ReconAgent ──▶ recon_results.json
                                                    │
                                                    ▼
vulnapp (running) ──HTTP──▶ ExploitAgent ──▶ exploit_results.json
                                                    │
                                                    ▼
vulnapp (running) ──HTTP──▶ ValidatorAgent ──▶ validation_report.json
                                                    │
                                                    ▼
vulnapp/app.py ──read──▶ PatchingAgent ──write──▶ vulnapp_patched/app.py
                                                    │
                                                    ▼
vulnapp_patched (running) ──HTTP──▶ ExploitAgent ──▶ (all FAILED = ✅)
```

### Communication Protocol

Agents do **not** communicate directly. They communicate through:
1. **State files** in `state/` — JSON outputs consumed by the next agent
2. **The file system** — PatchingAgent reads/writes source code files
3. **HTTP** — Agents make requests to the target; they do not call each other

---

## 3. Agent Roles & Responsibilities

### 3.1 ReconAgent (`agents/recon_agent.py`)

**Role**: Red team reconnaissance specialist  
**Input**: Target URL (CLI argument)  
**Output**: `state/recon_results.json`

**What it does**:
- Port scans common web ports using raw `socket` connections
- Probes a list of known paths (GET + POST) to discover endpoints
- Fingerprints the tech stack from response headers and body content
- Audits for missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Extracts HTML forms and checks for CSRF token fields
- Catalogs all discovered attack surfaces with severity ratings

**Key design decisions**:
- Uses `socket.create_connection()` with 1s timeout for fast port scanning
- Does NOT use `nmap` by default (requires system install); uses pure Python socket
- `port_scan=False` flag skips port scanning for faster runs
- All HTTP requests go through `BaseAgent.safe_request()` which swallows exceptions

**Attack vector catalog schema**:
```json
{
  "id": "sqli_login",
  "endpoint": "/login",
  "type": "sql_injection",
  "method": "POST",
  "params": ["username", "password"],
  "severity": "CRITICAL",
  "rationale": "..."
}
```

---

### 3.2 ExploitAgent (`agents/exploit_agent.py`)

**Role**: Offensive security payload executor  
**Input**: `state/recon_results.json` (falls back to built-in defaults)  
**Output**: `state/exploit_results.json`

**What it does**:
- Reads attack vectors from recon output
- Dispatches to the correct attack module per vector type
- Executes each payload from the JSON payload library
- Records request details, response details, and raw indicators
- Classifies each attempt as `POTENTIAL_SUCCESS` or `FAILED`

**Attack modules**:

| Module | Technique | Endpoint |
|---|---|---|
| `_exploit_sqli()` | POST form with injected SQL | `/login` |
| `_exploit_path_traversal()` | GET with `?name=../../..` | `/file` |
| `_exploit_csrf()` | POST from forged origin, no cookie | `/transfer` |
| `_exploit_cmdi()` | POST JSON with shell metacharacters | `/ping` |
| `_exploit_hardcoded_creds()` | GET with header brute force | `/admin` |
| `_exploit_jwt()` | Bearer token: alg:none / weak secret | `/api/profile` |

**Important**: ExploitAgent only assigns `POTENTIAL_SUCCESS` — it does NOT confirm.
Confirmation is the ValidatorAgent's job (separation of concerns).

**Exploit result schema**:
```json
{
  "id": "sqli_001_sqli_login",
  "type": "sql_injection",
  "endpoint": "/login",
  "payload_id": "sqli_001",
  "payload": "' OR '1'='1",
  "method": "POST",
  "request_data": {"username": "' OR '1'='1", "password": "x"},
  "response_status": 200,
  "response_body": "...(first 500 chars)...",
  "indicators": ["welcome_message", "jwt_token_returned"],
  "raw_outcome": "POTENTIAL_SUCCESS"
}
```

---

### 3.3 ValidatorAgent (`agents/validator_agent.py`)

**Role**: Evidence analyst and exploit classifier  
**Input**: `state/exploit_results.json`  
**Output**: `state/validation_report.json`

**What it does**:
- Iterates all exploit results from ExploitAgent
- Applies type-specific confirmation rules (indicator checklist)
- Re-runs `POTENTIAL_SUCCESS` exploits up to N times for confirmation
- Assigns `CONFIRMED | PARTIAL | FAILED` classification
- Assigns CVSS-lite severity scores
- Provides remediation hints for confirmed findings

**Confirmation rule logic**:
```python
# For each exploit:
required_indicators = CONFIRMATION_RULES[exploit_type]
matched = [i for i in exploit["indicators"] if i in required_indicators]

if raw_outcome == "POTENTIAL_SUCCESS" and len(matched) >= 1:
    if reconfirm_passes:
        status = "CONFIRMED"
    else:
        status = "PARTIAL"
else:
    status = "FAILED"
```

**Confirmation rules reference**:
```python
CONFIRMATION_RULES = {
    "sql_injection":         ["welcome_message", "jwt_token_returned", "sql_error_leaked"],
    "path_traversal":        ["etc_passwd_content", "source_code_exposed"],
    "csrf":                  ["action_confirmed", "password_changed"],
    "command_injection":     ["user_id_leaked", "etc_passwd_leaked"],
    "hardcoded_credentials": ["admin_data_returned"],
    "broken_jwt":            ["admin_role_confirmed", "privileged_data_returned"],
}
```

**Finding schema**:
```json
{
  "id": "sqli_001_sqli_login",
  "type": "sql_injection",
  "endpoint": "/login",
  "status": "CONFIRMED",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "evidence": ["Matched indicators: welcome_message", "HTTP 200 returned"],
  "remediation_hint": "Use parameterized queries..."
}
```

---

### 3.4 PatchingAgent (`agents/patching_agent.py`)

**Role**: Blue team automated remediation engineer  
**Input**: `state/validation_report.json` + `vulnapp/app.py` source  
**Output**: `vulnapp_patched/app.py`, `state/patch_report.json`, `state/final_report.md`

**What it does**:
- Reads only `CONFIRMED` findings from the validation report
- Copies `vulnapp/` → `vulnapp_patched/` (preserves original)
- Applies one patch per vulnerability type (rule-based string replacement)
- Always applies deployment hardening (configurable bind, debugger off, seed-dir fix)
- **Verifies its own output** before declaring the phase complete
- Displays a colored diff for each patch
- Generates a comprehensive `final_report.md`

**Patch strategies**:

| Vuln Type | Strategy | CWE |
|---|---|---|
| SQL Injection | Replace f-string SQL with `?` parameterized query | CWE-89 |
| Path Traversal | Add `os.path.realpath()` + `startswith(base_dir)` | CWE-22 |
| CSRF | Add `secrets.token_hex(32)` + `@csrf_protect` decorator | CWE-352 |
| Command Injection | Replace `shell=True` with list-form + regex whitelist | CWE-78 |
| Hardcoded Creds | Env var + random `secrets.token_urlsafe(32)` fallback; **every** reference renamed | CWE-798 |
| Broken JWT | Remove `verify_signature=False`, disallow `alg:none` | CWE-347 |
| Runtime hardening | `HOST`/`PORT` from env (default `127.0.0.1:5001`), `debug=False`, seed `files/` next to `app.py` | CWE-489 |

**Patch application is idempotent**: Running the agent twice produces the same result.
If a patch target string is not found (already patched), the patch is skipped gracefully.

**Output verification** (recorded in `patch_report.json` → `verification`):

| Check | Catches |
|---|---|
| `compile()` the patched source | Syntax errors from a bad replacement |
| Stale-symbol scan (`HARDCODED_ADMIN_PASSWORD`, `admin123`) | Half-applied renames → `NameError` at startup |
| Smoke test: boot the app on a free port, poll `/health` | Any patch that leaves the app unstartable |

A patch that leaves `vulnapp_patched/` unable to run is reported with the captured
startup output in `verification.smoke_detail`, instead of silently shipping a
broken deployment directory.

> The runtime-hardening patch is what allows Phase 5 (`--mode re-exploit`) to work:
> the patched app can run on port **5001** alongside the original on 5000.

---

## 4. Shared State Contract

All agents read from and write to `state/`. The order of operations is strict:

| File | Written By | Read By |
|---|---|---|
| `state/recon_results.json` | ReconAgent | ExploitAgent |
| `state/exploit_results.json` | ExploitAgent | ValidatorAgent |
| `state/validation_report.json` | ValidatorAgent | PatchingAgent |
| `state/patch_report.json` | PatchingAgent | GUI / Human |
| `state/final_report.md` | PatchingAgent | GUI / Human / Next Agent |
| `state/reexploit_results.json` | ExploitAgent (Phase 5) | ValidatorAgent (Phase 5) |
| `state/revalidation_report.json` | ValidatorAgent (Phase 5) | GUI / Human |
| `state/sast_report.json` | SastAgent | PatchingAgent (`--patch-sast`), GUI |
| `state/sast_report_patched.json` | SastAgent (Phase 5b) | GUI / Human |
| `state/dast_report.json` | DastAgent | GUI / Human |
| `state/dast_report_patched.json` | DastAgent (Phase 5c) | GUI / Human |
| `state/pipeline.log` | GUI runner (subprocess tee) | GUI live console |

**Phase 5 keeps its own files.** The re-exploit/re-validation pair targets the *patched*
app, so writing to `exploit_results.json` / `validation_report.json` would destroy the
original target's findings. Any agent can be pointed at a different output file with
`output_file="..."` (see `Agent(output_file=...)`), which is exactly what Phase 5 does:

```
vulnapp:5000   → exploit_results.json        → validation_report.json        (Phase 2/3)
vulnapp_patched:5001 → reexploit_results.json → revalidation_report.json      (Phase 5)
```

Each agent declares its output filename via the `state_filename` class attribute
(`BaseAgent._save_state` falls back to `<agentname>_results.json` when it is unset).
This is what keeps the contract above intact — change it and the next phase will
fail with `<file> not found`.


**All state files include a `_meta` block**:
```json
{
  "_meta": {
    "agent": "ExploitAgent",
    "target": "http://localhost:5000",
    "timestamp": "2026-09-04T10:00:00Z",
    "duration_s": 42.3
  }
}
```

**To reset state** (start fresh):
```bash
python scripts/reset_state.py
```

---

## 5. How to Run the Pipeline

### Prerequisites

```bash
# Install Python dependencies (includes Flask for the optional dashboard)
pip install -r requirements.txt

# Start the vulnerable target (native Python — no Docker needed)
python vulnapp/app.py          # → http://localhost:5000

# Or with Docker
docker compose up -d vulnapp

# Wait for target to be healthy
curl http://localhost:5000/health
```

### Run Modes

```bash
# Full pipeline (recommended)
python main.py --target http://localhost:5000 --mode full

# With patched app re-verification
python main.py \
  --target http://localhost:5000 \
  --patched-target http://localhost:5001 \
  --mode full

# Individual phases
python main.py --mode recon-only   --target http://localhost:5000
python main.py --mode exploit-only --target http://localhost:5000
python main.py --mode patch-only   --target http://localhost:5000
python main.py --mode re-exploit   --patched-target http://localhost:5001

# Web dashboard (see section 12) — terminal output is still preserved
python main.py --gui                       # http://127.0.0.1:5002
python main.py --gui --gui-port 8080

# Using the shell script (Linux/Mac)
./scripts/run_pipeline.sh http://localhost:5000 http://localhost:5001
```

### Windows console encoding

The Rich banner uses Unicode box-drawing characters. On legacy `cp1252` consoles
set UTF-8 first, otherwise Python raises `UnicodeEncodeError` before the pipeline
starts:

```powershell
$env:PYTHONIOENCODING = "utf-8"   # or run: chcp 65001
python main.py --target http://localhost:5000 --mode full
```

The GUI sets this automatically for every run it launches.


### Expected Output

```
Phase 1: Reconnaissance
  ✓ Endpoints found: 12
  ✓ Attack vectors: 7
  ✓ Open ports: [5000]

Phase 2: Exploitation
  POTENTIAL_SUCCESS  sql_injection        /login     [sqli_001]
  POTENTIAL_SUCCESS  path_traversal       /file      [pt_001]
  POTENTIAL_SUCCESS  command_injection     /ping      [cmdi_001]
  ...

Phase 3: Validation
  CONFIRMED     sql_injection        /login
  CONFIRMED     path_traversal       /file
  CONFIRMED     command_injection     /ping
  ...

Phase 4: Patching
  → Patching: sql_injection
  → Patching: path_traversal
  ✓ Patched source written to: vulnapp_patched/app.py
  ✓ Final report: state/final_report.md
```

---

## 6. Agent Development Guide

### Creating a New Agent

All agents inherit from `BaseAgent`. Minimum implementation:

```python
from agents.base_agent import BaseAgent

class MyNewAgent(BaseAgent):
    def __init__(self, target_url: str):
        super().__init__("MyNewAgent", target_url, timeout=10)

    def run(self) -> dict:
        # Your agent logic here
        data = self._load_state("recon_results.json")  # Read state
        results = {"findings": []}
        # ... do work ...
        return results   # Will be auto-saved to state/mynewagent_results.json
```

### BaseAgent API Reference

```python
# HTTP helpers
self.get("/path", params={})            → Response
self.post("/path", data={}, json={})    → Response
self.safe_request("GET", "/path")       → Response | None  (swallows exceptions)

# State I/O
self._load_state("filename.json")       → dict
self._save_state(data, "filename.json") → None  (auto-called by execute())
self._load_payloads("sqli_payloads.json") → list[dict]

# Logging
self.logger.info("message")
self.logger.warning("message")
self.logger.error("message")
self.log_finding("CRITICAL", "description")   # Colored output

# Lifecycle
self.check_target_alive()               → bool
self.setup()    # Override for pre-run logic
self.teardown() # Override for cleanup
```

### Adding a New Exploit Module

1. Add payloads to `payloads/my_attack_payloads.json`
2. Add a handler method to `ExploitAgent`:
   ```python
   def _exploit_my_attack(self, vector: dict) -> list[dict]:
       payloads = self._load_payloads("my_attack_payloads.json")
       results = []
       for p in payloads:
           resp = self.safe_request("POST", vector["endpoint"], ...)
           indicators = self._analyze_response(resp)
           outcome = "POTENTIAL_SUCCESS" if indicators else "FAILED"
           results.append({...})
       return results
   ```
3. Register it in `_run_vector()`:
   ```python
   dispatch = {
       ...
       "my_attack": self._exploit_my_attack,
   }
   ```
4. Add confirmation rules to `ValidatorAgent.CONFIRMATION_RULES`
5. Add a patch handler to `PatchingAgent._apply_patch()`
6. Add severity/CVSS to `ValidatorAgent.SEVERITY_CVSS`

---

## 7. Payload Library Reference

### sqli_payloads.json

Each payload targets the `username` field of the `/login` endpoint.

| ID | Payload | Technique |
|---|---|---|
| sqli_001 | `' OR '1'='1` | Always-true WHERE clause |
| sqli_002 | `admin'--` | SQL comment to bypass password |
| sqli_003 | `' UNION SELECT 1,2,3--` | UNION-based column probe |
| sqli_004 | `' OR SLEEP(3)--` | Blind time-based detection |
| sqli_005 | `' UNION SELECT sqlite_version(),2--` | Version extraction |

### path_traversal_payloads.json

Targets the `name` query parameter of the `/file` endpoint.

| ID | Payload | Bypasses |
|---|---|---|
| pt_001 | `../../../../etc/passwd` | No encoding filter |
| pt_002 | `..%2F..%2Fetc%2Fpasswd` | URL decode filter |
| pt_003 | `..%252Fetc%252Fpasswd` | Double URL encode |
| pt_004 | `..\\..\\..\windows\system.ini` | Windows paths |
| pt_005 | `../app.py` | Source code read |

### jwt_payloads.json

| ID | Technique | Description |
|---|---|---|
| jwt_001 | `alg_none` | Forges token with empty signature |
| jwt_002 | `weak_secret` | Brute forces common HMAC secrets |
| jwt_003 | `claim_tamper` | Modifies `role` claim to `admin` |

### Adding New Payloads

All payload files follow this schema:
```json
{
  "id": "unique_identifier",
  "name": "Human-readable name",
  "payload": "the actual attack string",
  "field": "target_form_field_or_param",
  "description": "What this payload does"
}
```

---

## 8. Target App (VulnApp) Reference

VulnApp is a purposefully vulnerable Flask application in `vulnapp/app.py`.

### Endpoint Map

| Endpoint | Method | Vulnerability | Severity |
|---|---|---|---|
| `GET /health` | GET | None (safe) | — |
| `GET /` | GET | Info disclosure (tech stack) | LOW |
| `POST /login` | POST | **SQL Injection** | CRITICAL |
| `GET /file` | GET | **Path Traversal** | HIGH |
| `POST /transfer` | POST | **CSRF** | HIGH |
| `GET /admin` | GET | **Hardcoded Credentials** | CRITICAL |
| `POST /ping` | POST | **Command Injection** | CRITICAL |
| `GET /api/profile` | GET | **Broken JWT** | HIGH |
| `POST /change_password` | POST | **CSRF** | HIGH |

### Database Schema

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,    -- VULN: plaintext passwords
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 1000.0
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    amount REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Seed credentials**:
- `admin` / `admin123` (role: admin, balance: 99999)
- `alice` / `alice_pass` (role: user, balance: 1000)
- `bob` / `bob_pass` (role: user, balance: 500)

### SQLi in Detail (`/login`)

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# Attack: username = "' OR '1'='1"
# Resulting query:
# SELECT * FROM users WHERE username='' OR '1'='1' AND password='x'
# → Returns first user (admin) because '1'='1' is always true
```

### Path Traversal in Detail (`/file`)

```python
# VULNERABLE
filepath = os.path.join(base_dir, filename)  # No canonicalization!
# Attack: filename = "../../../../etc/passwd"
# os.path.join("/app/files", "../../../../etc/passwd") = "/etc/passwd"
```

### Command Injection in Detail (`/ping`)

```python
# VULNERABLE
result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
# Attack: host = "127.0.0.1; id"
# Shell executes: ping -c 1 127.0.0.1; id
# Output includes: uid=0(root) gid=0(root) groups=0(root)
```

### JWT Bypass in Detail (`/api/profile`)

```python
# VULNERABLE
payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])
# Attack: forge header {"alg": "none"}, payload {"user": "admin", "role": "admin"}, empty signature
# Token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
# → Accepted because signature verification is disabled!
```

---

## 9. Extending CyberPulse

### Adding a Second Target (e.g., Node.js/Express)

1. Create `vulnapp_node/` with a purposefully vulnerable Express app
2. Add a service to `docker-compose.yml` (port 5002)
3. Create target-specific payloads if needed
4. ReconAgent auto-discovers endpoints — no changes needed
5. ExploitAgent works against any HTTP target — no changes needed
6. PatchingAgent needs new patch handlers for JS source code

### Adding LLM-Powered Patching

Replace rule-based patches in `PatchingAgent` with LLM calls:

```python
import openai  # or google.generativeai

def _patch_with_llm(self, source: str, vuln_type: str, finding: dict) -> tuple:
    prompt = f"""
    You are a security engineer. The following Python Flask code has a {vuln_type} vulnerability.
    Fix ONLY the vulnerability. Do not change other code. Return only the fixed Python source.

    VULNERABILITY: {finding['remediation_hint']}
    SOURCE:
    {source}
    """
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content, {"type": vuln_type, "method": "llm"}
```

### Upgrading the State Store

Replace JSON files with SQLite or Redis for concurrent multi-agent runs:

```python
# In base_agent.py, replace _save_state / _load_state with:
import sqlite3

def _save_state(self, data: dict, key: str = None) -> None:
    key = key or self.name
    conn = sqlite3.connect("state/cyberpulse.db")
    conn.execute("INSERT OR REPLACE INTO state (key, data, ts) VALUES (?,?,?)",
                 (key, json.dumps(data), datetime.utcnow().isoformat()))
    conn.commit()
```

### Adding Async/Parallel Exploitation

For faster exploitation, run payloads concurrently using `asyncio` + `httpx`:

```python
import asyncio
import httpx

async def _exploit_sqli_async(self, vector: dict) -> list:
    payloads = self._load_payloads("sqli_payloads.json")
    async with httpx.AsyncClient() as client:
        tasks = [client.post(f"{self.target_url}/login", data={"username": p["payload"]})
                 for p in payloads]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    return [self._analyze(r, p) for r, p in zip(responses, payloads)]
```

---

## 10. Troubleshooting

### Target is unreachable

```
[ERROR] [ReconAgent] Target unreachable at http://localhost:5000
```

**Fix**: Ensure the Docker container is running:
```bash
docker compose up -d vulnapp
docker compose logs vulnapp
curl http://localhost:5000/health
```

### exploit_results.json not found

```
[ERROR] State file not found: state/exploit_results.json
```

**Fix**: Run phases in order. The exploit phase must run before validation:
```bash
python main.py --mode full   # Runs all phases in correct order
```

### Patches not applied (no match in source)

PatchingAgent uses exact string matching. If the vulnerable source was edited,
the patch target string may no longer match. **Fix**: 
- Reset: `python scripts/reset_state.py`
- Restore original: `git checkout vulnapp/app.py` (if using git)

### `vulnapp_patched/app.py` will not start

The patcher verifies its own output (syntax → stale-symbol scan → smoke test) and
reports the result in `state/patch_report.json` under `verification`. Check that
block first:

```bash
python -c "import json;print(json.load(open('state/patch_report.json'))['verification'])"
```

Common causes:

| Symptom | Cause / Fix |
|---|---|
| `NameError: HARDCODED_ADMIN_PASSWORD` | An old, incomplete patch. Re-run `python main.py --mode patch-only` (current patcher renames every reference). |
| `RuntimeError: ADMIN_PASSWORD env variable must be set!` | Old patch variant. Current patcher uses a random fallback so the app always boots. |
| `smoke_test: "failed"` + startup output | Read `smoke_detail`; a crash at import is reproduced there verbatim. |
| `PermissionError: [WinError 32] ... vulnapp_patched` | A patched app instance is still running and holds the directory. Stop it (e.g. the server on port 5001) and re-run. |

### Port already in use (5001 / 5002)

```bash
# Windows: find and stop the listener
netstat -ano | findstr :5001
taskkill /F /T /PID <pid>
```


### JWT brute force misses the secret

The weak secret brute force only tries the wordlist in `jwt_payloads.json`.
Add the actual app secret to the wordlist, or extract it from the app source
using the path traversal exploit result (`../app.py` → find `secret_key`).

### Windows-specific: `ping -c 1` not found

The VulnApp's `/ping` endpoint uses Linux `ping -c 1`. On Windows hosts:
- Run VulnApp inside Docker (recommended)
- Or change to `ping -n 1` in `vulnapp/app.py`

---

## 11. Security Concepts Reference

### SQL Injection (CWE-89)

**What**: Attacker injects SQL syntax into a query via user input.  
**Why possible**: String interpolation (`f"... {user_input} ..."`) in SQL queries.  
**Fix**: Parameterized queries — `db.execute("SELECT * FROM x WHERE y=?", (value,))`  
**CVSS**: 9.8 (Critical)

### Path Traversal (CWE-22)

**What**: Attacker reads files outside the intended directory using `../` sequences.  
**Why possible**: `os.path.join(base, user_input)` without canonicalization.  
**Fix**: `realpath()` + `startswith(base_dir)` boundary check.  
**CVSS**: 7.5 (High)

### CSRF — Cross-Site Request Forgery (CWE-352)

**What**: Attacker tricks a logged-in user's browser into making unauthorized requests.  
**Why possible**: State-changing endpoints don't require a secret token known only to the origin.  
**Fix**: CSRF tokens in forms + `SameSite=Strict` cookies.  
**CVSS**: 7.1 (High)

### Command Injection (CWE-78)

**What**: Attacker injects shell commands via user-controlled input passed to `shell=True`.  
**Why possible**: `subprocess(..., shell=True, ...)` with unsanitized input.  
**Fix**: List-form subprocess (`["ping", "-c", "1", host]`) + input whitelist.  
**CVSS**: 9.8 (Critical)

### Hardcoded Credentials (CWE-798)

**What**: Secret credentials embedded in source code, exposable via code review or path traversal.  
**Why possible**: Convenience during development, never removed.  
**Fix**: `os.environ.get("SECRET")` + secrets manager (Vault, AWS Secrets Manager).  
**CVSS**: 9.1 (Critical)

### Broken JWT (CWE-347 / JWT `alg:none`)

**What**: Server accepts unsigned JWT tokens, allowing attackers to forge any identity.  
**Why possible**: `verify_signature=False` or accepting `alg:none` in JWT decode.  
**Fix**: Always specify exact algorithms; never accept `none`; verify with the server secret.  
**CVSS**: 8.1 (High)

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────────┐
│  RUN FULL PIPELINE                                                  │
│  python main.py --target http://localhost:5000 --mode full          │
│                                                                     │
│  RUN TESTS                                                          │
│  pytest tests/ -v                                                   │
│                                                                     │
│  RESET STATE                                                        │
│  python scripts/reset_state.py                                      │
│                                                                     │
│  START TARGET                                                       │
│  docker compose up -d vulnapp                                       │
│                                                                     │
│  WEB DASHBOARD (for demos)                                          │
│  python main.py --gui            → http://127.0.0.1:5002           │
│  (terminal output is still printed by the CLI subprocess)           │
│                                                                     │
│  VIEW FINAL REPORT                                                  │
│  cat state/final_report.md                                          │
│                                                                     │
│  AGENT STATE FILES                                                  │
│  state/recon_results.json      ← After Phase 1                     │
│  state/exploit_results.json    ← After Phase 2                     │
│  state/validation_report.json  ← After Phase 3                     │
│  state/patch_report.json       ← After Phase 4 (+ verification)    │
│  state/final_report.md         ← After Phase 4                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 12. Web Dashboard (GUI)

The CLI is the source of truth — the dashboard is a **viewer + launcher** layered
on top of it, so it is safe for live demos.

```bash
python main.py --gui                    # http://127.0.0.1:5002
python main.py --gui --gui-port 8080    # custom port
python gui/app.py --port 8080           # standalone
```

### How it works

```
browser ──HTTP──▶ gui/app.py (Flask, port 5002)
                     │  POST /api/run
                     ▼
                 subprocess: python main.py <mode> <target>
                     ├──▶ terminal you launched the GUI from  (unchanged CLI UX)
                     ├──▶ state/pipeline.log                  (durable log)
                     └──▶ GET /api/log?offset=N               (browser console)
```

* **Terminal is preserved.** `main.py` runs as a child process with unbuffered
  UTF-8 output, tee'd to your terminal *and* to the browser.
* **Phase roll-up** is derived from the `Phase N:` banners in the log; phases that
  never ran (e.g. `recon-only`) show as *skipped* once the run completes.
* **Read-only data views** come straight from the state contract files, so the GUI
  can never disagree with the CLI output.

### API

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/report` | GET | Final report rendered from markdown |
| `/api/health` | GET | Liveness probe |
| `/api/status` | GET | Runner state + phase roll-up |
| `/api/run` | POST | Start a run (`mode`, `target`, `patched_target`, `timeout`, `port_scan`) |
| `/api/stop` | POST | Stop the run (kills the child process tree) |
| `/api/log?offset=N` | GET | Incremental log lines for live streaming |
| `/api/state/<file>` | GET | Raw state JSON (allow-listed files only) |
| `/api/report` | GET | Raw markdown of `final_report.md` |

Only these state files are readable through the API:
`recon_results.json`, `exploit_results.json`, `validation_report.json`,
`patch_report.json`, `reexploit_results.json`, `revalidation_report.json`.
Everything else returns `403`.

### Dashboard panels

| Panel | Source |
|---|---|
| Phase stepper | `Phase N:` banners in the log (+ runner exit status) |
| Live console | `state/pipeline.log` (incremental, offset-polled) |
| Metrics | `validation_report.json` summary + `patch_report.json` |
| Confirmed findings | `validation_report.json` (`CONFIRMED` only) |
| Patches & verification | `patch_report.json` (`patches`, `verification`) |
| Phase 5 verdict | `revalidation_report.json` — *REMEDIATED* when 0 confirmed |
| Recon summary | `recon_results.json` |


### Security notes

* Binds to `127.0.0.1` by default — it launches real attack tooling, so never
  expose it to a network.
* The dashboard does not add new attack capability; it only wraps the same
  orchestrator you can run manually.

---

## 13. SAST & DAST Scanners

Two optional agents turn the exploit-only swarm into a full AppSec loop:

| Agent | Phase | Tool | Requirement | Output |
|---|---|---|---|---|
| `SastAgent` | 1b | Semgrep | native CLI **or** Docker | `state/sast_report.json` |
| `DastAgent` | 3b | OWASP ZAP | **Docker** | `state/dast_report.json` |

They run **before and after** patching, which is the point: the re-scan is
independent evidence that the fix landed (static) and holds under attack (dynamic).

```
Recon → SAST → Exploit → Validate → DAST → Patch → Re-Exploit → SAST/DAST re-scan
```

### 13.1 SastAgent (Semgrep)

**Command construction** (`_build_command`):

```
native : semgrep --json --output <tmp> --metrics=off --config <rules.yml> <paths>
docker : docker run --rm -v <repo>:/src:ro -w /src semgrep/semgrep \
                   semgrep --json --output <tmp> --config <rules.yml> <paths>
```

* Tool discovery order: `semgrep` on `PATH` → `docker` → `{"status": "skipped"}` with install hints.
* Exit code `1` means *findings found* and is treated as success; other non-zero codes are errors.
* Paths are emitted as **POSIX** (forward slashes) so the same arguments work on
  Windows and inside the Linux container.
* Telemetry and the version check are disabled (`SEMGREP_SEND_METRICS=off`).

**Rule pack** — `configs/semgrep/cyberpulse.yml` (8 rules):

| Rule | CWE | Fires on |
|---|---|---|
| `sql-injection-fstring` | CWE-89 | f-string `SELECT` built and executed |
| `sql-injection-string-format` | CWE-89 | `%` / `.format()` SQL assembly |
| `command-injection-shell-true` | CWE-78 | `shell=True`, `os.system`, `os.popen` |
| `path-traversal-unvalidated-open` | CWE-22 | `open(os.path.join(...))` without `realpath` |
| `hardcoded-credential` | CWE-798 | `password/secret/token = "<literal>"` |
| `jwt-verification-disabled` | CWE-347 | `verify_signature: False`, `alg: none` |
| `flask-debug-enabled` | CWE-489 | `app.run(debug=True)` |
| `flask-hardcoded-secret-key` | CWE-798 | `app.secret_key = "..."` |

Each rule matches only the **vulnerable** form, so remediation makes it go quiet — that
is what makes the re-scan meaningful.

**Normalized finding**:

```json
{
  "id": "configs.semgrep.cyberpulse.sql-injection-fstring:vulnapp/app.py:104",
  "rule": "configs.semgrep.cyberpulse.sql-injection-fstring",
  "severity": "HIGH",              // ERROR→HIGH, WARNING→MEDIUM, INFO→LOW
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "file": "vulnapp/app.py",
  "line": 104,
  "confidence": "HIGH"
}
```

### 13.2 DastAgent (OWASP ZAP)

```
docker run --rm \
  -v <repo>/state/zap:/zap/wrk:rw \
  -v <repo>/configs/zap:/zap/configs:ro \
  [--network host] \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t <target> -J <json> -r <html> -w <md> \
    -m <spider_min> -I -s -c /zap/configs/baseline.conf
```

* **Scan profiles**: `baseline` (`zap-baseline.py`: passive + spider, safe, 1–3 min) and
  `full` (`zap-full-scan.py`: active attacks incl. SQLi/XSS probes, 10–30 min, intrusive).
* **Container → host reachability** is handled automatically:

  | Host | Network mode | Target passed to the container |
  |---|---|---|
  | Linux / WSL2 (Docker Engine) | `--network host` | unchanged (`http://127.0.0.1:5000`) |
  | Windows / macOS (Docker Desktop) | bridge | `localhost` → `host.docker.internal` |

  Override with `network_mode="host"|"bridge"`.
* Exit codes `0/1/2` count as "scan completed" (warnings/failures are data, not errors);
  the JSON report is the source of truth.
* Raw reports are kept in `state/zap/` (JSON, HTML, Markdown).

**Normalized finding**:

```json
{
  "id": "40018:SQL Injection",
  "plugin_id": "40018",
  "name": "SQL Injection",
  "severity": "HIGH",          // riskcode 3→HIGH, 2→MEDIUM, 1→LOW, 0→INFO
  "confidence": "MEDIUM",
  "cwe": "CWE-89",
  "endpoint": "http://localhost:5000/login",
  "instances": 2,
  "solution": "Use parameterized queries."
}
```

### 13.3 Scan policy

`configs/zap/baseline.conf` tunes noise per rule id:

```
10011	IGNORE	# Cookie Without Secure Flag — plain HTTP sandbox
10020	WARN	# Missing Anti-clickjacking Header
40018	FAIL	# SQL Injection (active scan only)
```

`IGNORE` drops the alert, `WARN` reports it, `FAIL` marks the run as failed.

### 13.4 SAST-driven patching (`--patch-sast`)

By default the patcher only fixes types that exploitation **confirmed**. SAST usually
reports more — e.g. `shell=True` and the hardcoded `app.secret_key`, which the exploit
suite never triggered because its payloads/indicators did not confirm them. With
`--patch-sast`, `PatchingAgent` merges SAST-reported types (via `SAST_RULE_TO_TYPE`)
into its patch targets:

```bash
python main.py --mode sast-only --sast-path vulnapp         # 6 findings
python main.py --mode patch-only --patch-sast               # 7 patches (4 confirmed + 3 SAST-only)
python main.py --mode sast-only --sast-path vulnapp_patched # 0 findings
```

Patches originating from SAST are labelled `"source": "sast"` in `patch_report.json`.
Added handlers: `flask_secret_key` (env var + random fallback) and `runtime_hardening`
(reuses the deployment-hardening patch).

### 13.5 Running the scanners

```bash
# individually
python main.py --mode sast-only --sast-path vulnapp
python main.py --mode dast-only --target http://localhost:5000 --zap-scan-type baseline

# inside a full run (adds the pre-scan and the post-patch re-scan)
python main.py --target http://localhost:5000 --patched-target http://localhost:5001 \
  --mode full --with-sast --with-dast
```

Compose services are available for Docker deployments:

```bash
docker compose up -d vulnapp
docker compose --profile scanners run --rm semgrep
docker compose --profile scanners run --rm zap   # targets http://vulnapp:5000 by service name
```

> Install/run instructions for Windows and WSL2 (Docker Engine setup, networking
> pitfalls, troubleshooting) are in
> **[WSL_SETUP_GUIDE.md](WSL_SETUP_GUIDE.md#security-scanners-sast--dast)**.

---

*CyberPulse Agent Guide — For Educational and Sandbox Use Only*  
*Built with Python 3.11 + Flask + Docker*
