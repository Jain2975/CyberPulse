# CyberPulse



**Autonomous Penetration Testing & Vulnerability Exploitation Swarm**  
A 4-agent AI security ecosystem that runs a full red-team → blue-team cycle autonomously. 3. Autonomous Penetration Testing & Vulnerability Exploitation Swarm
Build an offensive/defensive security team agent ecosystem designed to run inside an isolated sandbox target environment (like a purposefully vulnerable local web app).

Architectural Challenge:

Recon Agent: Runs network scans, maps endpoints, identifies technology stacks, and catalogs attack vectors.

Exploit Agent: Formulates payloads (e.g., SQLi, CSRF, authentication bypass, path traversal) and executes attack scripts against the target.

Validator Agent: Analyzes response signatures, status codes, and database state changes to verify if an exploit succeeded.

Patching Agent: Reads the source code of the vulnerable application, generates security fixes, applies them, and re-runs the exploit suite to verify remediation.

Why It’s Tough: Forces agents to handle complex multi-step reasoning chains, execute shell tools dynamically, interpret structured/unstructured outputs, and write precise code fixes.
I am thinking doing this and SO I need you to make a very good Guide IN this SO that IN future I can give it to other agents as well .. OK And also need to do planning and all and make starting files as well

---

## Pipeline

```
Recon → Exploit → Validate → Patch → Re-Exploit
```

With the optional scanners enabled (`--with-sast` / `--with-dast`):

```
Recon → SAST → Exploit → Validate → DAST → Patch → Re-Exploit → SAST/DAST re-scan
```

| Phase | Agent          | Does                                                                         |
| ----- | -------------- | ---------------------------------------------------------------------------- |
| 1     | ReconAgent     | Maps endpoints, fingerprints stack, catalogs attack vectors                  |
| 1b    | SastAgent      | Semgrep static analysis of the source (+ re-scan of the patched copy)        |
| 2     | ExploitAgent   | Fires 6 attack types: SQLi, path traversal, CSRF, CMDi, hardcoded creds, JWT |
| 3     | ValidatorAgent | Re-verifies potential successes, assigns CONFIRMED/PARTIAL/FAILED + CVSS     |
| 3b    | DastAgent      | OWASP ZAP dynamic scan of the running target (+ re-scan of the patched app)  |
| 4     | PatchingAgent  | Reads source, applies targeted patches, writes `vulnapp_patched/`            |
| 5     | Re-Exploit     | Verifies all fixed vulnerabilities now return FAILED                         |

## Security Scanners

| Scanner | Tool | Requirement | Output |
| ------- | ---- | ----------- | ------ |
| SAST | [Semgrep](https://semgrep.dev) | native CLI or Docker | `state/sast_report.json` |
| DAST | [OWASP ZAP](https://www.zaproxy.org) | **Docker** | `state/dast_report.json` |

```bash
# SAST — static analysis (no Docker needed)
python main.py --mode sast-only --sast-path vulnapp
python main.py --mode sast-only --sast-path vulnapp_patched   # prove the fix

# DAST — dynamic analysis (needs Docker)
python main.py --mode dast-only --target http://localhost:5000
python main.py --mode dast-only --target http://localhost:5000 --zap-scan-type full

# Everything, including a re-scan after patching
python main.py --target http://localhost:5000 --patched-target http://localhost:5001 \
  --mode full --with-sast --with-dast
```

Custom rule packs ship with the project:

* `configs/semgrep/cyberpulse.yml` — 8 rules covering the VulnApp vulnerability classes
* `configs/zap/baseline.conf` — ZAP scan policy (INFO / WARN / FAIL per rule id)

Install and Docker instructions live in **[WSL_SETUP_GUIDE.md](WSL_SETUP_GUIDE.md#security-scanners-sast--dast)**.

---

## Quick Start (No Docker Needed!)

CyberPulse works 100% natively on **Windows (PowerShell)** or in **WSL2 (Ubuntu)** without needing Docker. See **[WSL_SETUP_GUIDE.md](WSL_SETUP_GUIDE.md)** for detailed WSL instructions.

```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install -r vulnapp/requirements.txt

# 2. Terminal 1: Start the vulnerable target
python vulnapp/app.py
# → Running on http://localhost:5000

# 3. Terminal 2: Run full pipeline
python main.py --target http://localhost:5000 --mode full

# 4. View final report
cat state/final_report.md
```

*(Optional: Docker is still supported via `docker compose up -d vulnapp` if preferred).*

> **Windows note:** if you see `UnicodeEncodeError`, your console is `cp1252`. Run
> `$env:PYTHONIOENCODING = "utf-8"` first (or use `chcp 65001`). The GUI sets this for you.

## Web Dashboard (for demos)

The CLI output is unchanged — the dashboard runs `main.py` as a subprocess and
**mirrors the same colored output** into the browser, so you can show the swarm
without squinting at a terminal.

```bash
# Terminal 1: vulnerable target
python vulnapp/app.py

# Terminal 2: dashboard (terminal output still prints here)
python main.py --gui                 # → http://127.0.0.1:5002
```

You get a live phase stepper, streaming console, confirmed-findings table
(severity + CVSS), patches applied **with patched-app verification status**, recon
summary, and a rendered final report at `/report`.

| Command | What it does |
| --- | --- |
| `python main.py --gui` | Dashboard on `127.0.0.1:5002` |
| `python main.py --gui --gui-port 8080` | Dashboard on a custom port |
| `python gui/app.py --port 8080` | Dashboard standalone |

It binds to localhost only and can read just an allow-listed set of state files
(recon/exploit/validation/patch, the Phase-5 re-verification files, and the SAST/DAST
reports) — see [AGENT_GUIDE.md](AGENT_GUIDE.md#12-web-dashboard-gui).


## Project Structure

```
CyberPulse/
├── AGENT_GUIDE.md          ← Comprehensive guide (read this first!)
├── WSL_SETUP_GUIDE.md      ← Windows/WSL setup + scanner installation
├── main.py                 ← Orchestrator + CLI (+ --gui dashboard mode)
├── configs/
│   ├── semgrep/cyberpulse.yml  ← SAST rule pack
│   └── zap/baseline.conf       ← DAST scan policy
├── agents/
│   ├── base_agent.py       ← Shared base class
│   ├── recon_agent.py      ← Phase 1
│   ├── sast_agent.py       ← Phase 1b (Semgrep)
│   ├── exploit_agent.py    ← Phase 2
│   ├── validator_agent.py  ← Phase 3
│   ├── dast_agent.py       ← Phase 3b (OWASP ZAP)
│   └── patching_agent.py   ← Phase 4 (+ patched-app verification)
├── gui/                    ← Web dashboard (Flask): app.py, templates/, static/
├── payloads/               ← JSON attack payload libraries
├── vulnapp/                ← Purposefully vulnerable Flask app
├── state/                  ← Agent outputs (auto-created)
├── scripts/                ← Utilities
└── tests/                  ← Pytest test suite
```

## Run Modes

```bash
python main.py --mode full          # All 5 phases
python main.py --mode recon-only    # Phase 1 only
python main.py --mode exploit-only  # Phases 2+3
python main.py --mode patch-only    # Phase 4 only
python main.py --mode re-exploit --patched-target http://localhost:5001
python main.py --mode sast-only     # Semgrep static analysis
python main.py --mode dast-only     # OWASP ZAP dynamic analysis (Docker)
python main.py --gui                # Web dashboard instead of a run
```

**Phase 5 note:** the patched app defaults to `127.0.0.1:5001` (the hardening patch
makes the bind configurable), so it can run alongside the original target:

```bash
python vulnapp_patched/app.py          # → :5001
python main.py --mode re-exploit --patched-target http://localhost:5001
```


## Built-in Vulnerabilities (VulnApp)

| Vuln                  | Endpoint           | CVSS |
| --------------------- | ------------------ | ---- |
| SQL Injection         | `POST /login`      | 9.8  |
| Command Injection     | `POST /ping`       | 9.8  |
| Hardcoded Credentials | `GET /admin`       | 9.1  |
| Broken JWT (alg:none) | `GET /api/profile` | 8.1  |
| Path Traversal        | `GET /file`        | 7.5  |
| CSRF                  | `POST /transfer`   | 7.1  |

## Run Tests

```bash
pytest tests/ -v
```

---

See **[AGENT_GUIDE.md](AGENT_GUIDE.md)** for the complete technical reference.
