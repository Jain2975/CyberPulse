# CyberPulse — WSL & Windows Setup Guide

This guide explains how to run **CyberPulse** natively on **Windows** or inside **WSL2 (Ubuntu)**.

> **Migrating to WSL + Docker:** the project is intended to live in **WSL2**, where the
> Docker engine is available. Docker is **optional** for the core swarm (Recon → Exploit →
> Validate → Patch) and **required** for DAST (OWASP ZAP) — ZAP ships as a container image.
> See [Security Scanners (SAST & DAST)](#security-scanners-sast--dast).

---

## Why You Don't Need Docker (for the core swarm)

Docker was originally used to isolate the target app. However, **VulnApp** is simply a lightweight Python Flask application using SQLite. You can run both the target and the agent swarm directly in Python on either Windows or WSL!

Both environments now support:
- ✅ Automatic OS detection for the ping command (`ping -n 1` on Windows, `ping -c 1` on Linux/WSL).
- ✅ Cross-platform database paths via `tempfile.gettempdir()`.
- ✅ Native socket port scanning and HTTP exploitation.
- ✅ SAST (Semgrep) natively or via container.
- ⚠️ DAST (OWASP ZAP) **requires Docker** — it is distributed as a container image.


---

## Option 1: Running on WSL2 (Ubuntu) — Recommended for Security Tooling

WSL2 provides a real Linux kernel, standard Linux CLI tools (`grep`, `curl`, `nmap`), and native POSIX paths.

### 1. Open WSL
In Windows Terminal or PowerShell, launch WSL:
```bash
wsl
```

### 2. Navigate to your project
Your Windows drives are automatically mounted under `/mnt/`:
```bash
cd /mnt/d/CyberPulse
```

### 3. Set up a Python Virtual Environment in WSL
```bash
# Update and install python3-venv / python3-pip if needed
sudo apt update && sudo apt install -y python3-venv python3-pip

# Create and activate virtual environment
python3 -m venv .venv-wsl
source .venv-wsl/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r vulnapp/requirements.txt
```

### 4. Run the Application & Agents

#### Terminal 1 (Target App):
```bash
source .venv-wsl/bin/activate
python vulnapp/app.py
# → Running on http://127.0.0.1:5000
```

#### Terminal 2 (CyberPulse Swarm):
```bash
source .venv-wsl/bin/activate
python main.py --target http://127.0.0.1:5000 --mode full
```

#### Or One-Shot Shell Script:
```bash
chmod +x scripts/run_pipeline.sh
./scripts/run_pipeline.sh http://127.0.0.1:5000
```

---

## Security Scanners (SAST & DAST)

CyberPulse can add **static** (Semgrep) and **dynamic** (OWASP ZAP) analysis to the
exploit-driven pipeline. Both write results into `state/`, and both run **before and
after** patching so you can prove the fix statically *and* dynamically.

| Scanner | Type | Tool | Runtime requirement | Output |
| --- | --- | --- | --- | --- |
| `SastAgent` | SAST | Semgrep | native CLI **or** Docker | `state/sast_report.json` |
| `DastAgent` | DAST | OWASP ZAP | **Docker required** | `state/dast_report.json` |

### 1. SAST — Semgrep

**Install in WSL2 (recommended, no Docker needed):**

```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
exec $SHELL                 # reload PATH
pipx install semgrep
semgrep --version           # → 1.xxx.x
```

Alternative (inside the project venv):

```bash
source .venv-wsl/bin/activate
pip install semgrep
```

Docker alternative (no local install):

```bash
docker pull semgrep/semgrep:latest
```

**Run it:**

```bash
# CyberPulse rule pack (8 rules covering the VulnApp vulnerability classes)
semgrep --config configs/semgrep/cyberpulse.yml --json vulnapp/

# via the agent (normalized report + pretty table)
python main.py --mode sast-only --sast-path vulnapp

# re-scan the remediated copy — this is the "did the fix land?" proof
python main.py --mode sast-only --sast-path vulnapp_patched

# add community rulesets on top (requires network access)
python main.py --mode sast-only --sast-path vulnapp   # extend with: --config p/owasp-top-ten
```

The agent auto-detects `semgrep` on `PATH`, otherwise it falls back to the
`semgrep/semgrep` container, otherwise it reports `status: "skipped"` with install hints.

### 2. DAST — OWASP ZAP

ZAP is only distributed as a container, so **Docker must be available**. In WSL2 you can
either install Docker Engine inside the distro or use Docker Desktop's WSL integration.

```bash
# Option A — Docker Engine inside WSL2 (Ubuntu)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER     # run docker without sudo
exec $SHELL
docker run --hello-world || docker run hello-world    # verify the engine works

# Option B — Docker Desktop for Windows with "WSL integration" enabled,
#            then run these commands from inside WSL.
```

Pull the ZAP image once:

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
```

**Run it through the agent:**

```bash
# baseline = passive rules + spider (safe and fast, ~1-3 min)
python main.py --mode dast-only --target http://127.0.0.1:5000

# full = active attacks (SQLi / XSS / path traversal probes) — slower, intrusive
python main.py --mode dast-only --target http://127.0.0.1:5000 --zap-scan-type full
```

**Raw equivalent** (what the agent executes), WSL2 with host networking so the
container can reach a target running on `localhost`:

```bash
docker run --rm --network host \
  -v "$PWD/state/zap:/zap/wrk:rw" \
  -v "$PWD/configs/zap:/zap/configs:ro" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
    -t http://127.0.0.1:5000 \
    -c /zap/configs/baseline.conf \
    -J zap_report.json -r zap_report.html -w zap_report.md \
    -m 2 -I -s
```

On **Windows / Docker Desktop** `--network host` does not route to the Windows host, so
target the host explicitly instead (the agent performs this rewrite automatically):

```powershell
docker run --rm `
  -v "${PWD}/state/zap:/zap/wrk:rw" `
  -v "${PWD}/configs/zap:/zap/configs:ro" `
  ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t http://host.docker.internal:5000 `
    -c /zap/configs/baseline.conf -J zap_report.json -I -s
```

Reports land in `state/zap/` (JSON + HTML + Markdown); normalized findings go to
`state/dast_report.json`.

### 3. Run the whole thing together

```bash
# Core swarm + both scanners + a re-scan of the patched app
python main.py \
  --target http://127.0.0.1:5000 \
  --patched-target http://127.0.0.1:5001 \
  --mode full \
  --with-sast \
  --with-dast
```

Phase order becomes:

```
Recon → SAST → Exploit → Validate → DAST → Patch → Re-Exploit → SAST/DAST re-scan
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--with-sast` | Semgrep before patching **and** a re-scan of `vulnapp_patched/` |
| `--with-dast` | ZAP before patching **and** a re-scan of the patched target |
| `--sast-path vulnapp` | Source path to scan (default `vulnapp`) |
| `--zap-scan-type baseline\|full` | ZAP profile (default `baseline`) |
| `--patch-sast` | Also remediate SAST-reported types (see below) |

### 4. SAST-driven patching (`--patch-sast`)

By default the patcher only fixes what exploitation **confirmed**. SAST often sees more
(e.g. `shell=True` and a hardcoded session key that the exploit suite never triggered).
With `--patch-sast` those types are remediated too:

```bash
python main.py --mode sast-only --sast-path vulnapp     # 1. scan
python main.py --mode patch-only --patch-sast           # 2. patch (exploit + SAST types)
python main.py --mode sast-only --sast-path vulnapp_patched   # 3. verify: 6 → 0
```

Patches that came from SAST are labelled `"source": "sast"` in `state/patch_report.json`.

### 5. Scanner state files

| File | Written by | Contents |
| --- | --- | --- |
| `state/sast_report.json` | SastAgent | Semgrep findings for the original source |
| `state/sast_report_patched.json` | SastAgent (Phase 5b) | Semgrep findings for `vulnapp_patched/` |
| `state/dast_report.json` | DastAgent | ZAP alerts for the original target |
| `state/dast_report_patched.json` | DastAgent (Phase 5c) | ZAP alerts for the patched target |
| `state/zap/zap_report_*.json` | ZAP container | Raw ZAP reports (JSON/HTML/Markdown) |

### 6. Running the scanners as Compose services (WSL + Docker)

`docker-compose.yml` includes both scanners under an opt-in `scanners` profile. Inside the
compose network ZAP reaches the target by **service name**, so you do not need
`--network host` or `host.docker.internal`:

```bash
# start the target
docker compose up -d vulnapp

# SAST — Semgrep over the source tree (read-only mount)
docker compose --profile scanners run --rm semgrep

# DAST — ZAP baseline against http://vulnapp:5000
docker compose --profile scanners run --rm zap
#   → reports: state/zap/zap_report.json / .html
```

Or drive everything from one command on the host:

```bash
WITH_SAST=1 WITH_DAST=1 ./scripts/run_pipeline.sh http://localhost:5000 http://localhost:5001
```

### 7. Migrating the project to WSL

Everything is path-relative to the project root, so the move is a copy plus a venv:

```bash
# 1. Copy (or clone) into the WSL filesystem — NOT /mnt/c, which is slow for I/O
mkdir -p ~/projects && cp -r /mnt/d/CyberPulse ~/projects/CyberPulse
cd ~/projects/CyberPulse

# 2. Python environment
sudo apt update && sudo apt install -y python3-venv python3-pip
python3 -m venv .venv-wsl && source .venv-wsl/bin/activate
pip install -r requirements.txt
pip install -r vulnapp/requirements.txt

# 3. Scanner tooling
pipx install semgrep                    # SAST (native)
curl -fsSL https://get.docker.com | sh  # DAST engine (ZAP is a container)
sudo usermod -aG docker "$USER" && exec $SHELL

# 4. Verify
pytest tests/ -q
semgrep --version && docker run --rm hello-world
```

Notes for the migration:

* `HOST`/`PORT` for the patched app are environment-driven (`127.0.0.1:5001` by default), so
  port bindings keep working after the move.
* The patched app rebuild (`vulnapp_patched/`) is a normal directory copy — on Windows a
  running instance locks it; on Linux the same applies to a process whose CWD is that folder.
* ZAP auto-selects `--network host` on Linux, which is what makes `http://127.0.0.1:5000`
  reachable from the container.

---

## Option 2: Running Directly on Native Windows (PowerShell)


If you prefer to stay in PowerShell without opening WSL, everything works natively!

### 1. Open PowerShell
```powershell
cd d:\CyberPulse
```

### 2. Set up a Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r vulnapp\requirements.txt
```

### 3. Run

#### PowerShell Window 1 (Target App):
```powershell
.\.venv\Scripts\Activate.ps1
python vulnapp\app.py
```

#### PowerShell Window 2 (Swarm Pipeline):
```powershell
.\.venv\Scripts\Activate.ps1
python main.py --target http://localhost:5000 --mode full
```

---

## Running the Unit Tests

The test suite runs identically in Windows and WSL:

```bash
# In Windows (PowerShell) or WSL (Bash):
pytest tests/ -v
```

The suite covers the full swarm, including the scanners (no Semgrep/Docker needed —
the tool invocation layer is mocked, so tests pass on any host):

| Test file | Covers |
| --- | --- |
| `tests/test_recon.py` | Port scanning, endpoint discovery, fingerprinting |
| `tests/test_exploit.py` | SQLi, CMDi, path traversal, JWT forgery, state-file contract |
| `tests/test_validator.py` | Confirmation rules and CVSS scoring |
| `tests/test_patcher.py` | Patch generation, AST validation, patched-app verification |
| `tests/test_sast.py` | Semgrep command building, JSON normalization, config/mapping consistency |
| `tests/test_dast.py` | ZAP command building, container URL rewriting, report normalization |
| `tests/test_gui.py` | Dashboard routes, state allow-list, markdown rendering |

---

## Scanner Troubleshooting (WSL / Docker)

### `semgrep: command not found`

```bash
pipx install semgrep          # or: pip install semgrep
pipx ensurepath && exec $SHELL
which semgrep
```

If Semgrep is not available at all, the agent reports `status: "skipped"` and the rest of
the pipeline continues.

### Semgrep is slow on first run

The first invocation may contact the registry for updates. The agent disables telemetry
and the version check; to suppress it globally:

```bash
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
```

### `permission denied while trying to connect to the Docker daemon socket`

```bash
sudo usermod -aG docker $USER    # add yourself to the docker group
exec $SHELL                      # or: newgrp docker
```

On WSL2 also confirm the engine is reachable: `docker run --rm hello-world`.

### ZAP cannot reach the target

| Environment | Fix |
| --- | --- |
| WSL2 + Docker Engine | Agent uses `--network host`; target `http://127.0.0.1:5000` |
| Docker Desktop (Win/macOS) | Agent rewrites to `http://host.docker.internal:5000` |
| Custom bridge network | Run the target as a container on the same network and pass its service name |

Force a mode explicitly if auto-detection picks the wrong one (Python API / dashboard):

```python
DastAgent(target_url="http://localhost:5000", network_mode="host")   # Linux/WSL2
DastAgent(target_url="http://localhost:5000", network_mode="bridge") # Docker Desktop
```

### ZAP scan takes too long / times out

```bash
# shorter spider/passive window via the agent's configuration
python -c "from agents import DastAgent; DastAgent('http://127.0.0.1:5000', spider_minutes=1, scan_timeout=600).execute()"
```

`baseline` is passive + spider only. `full` performs active attacks and takes much longer —
budget 10–30 minutes for a full scan.

### ZAP reports a rule you want to ignore (or fail on)

Edit `configs/zap/baseline.conf`:

```
10096	IGNORE	# Timestamp Disclosure - Unix
40018	FAIL	# SQL Injection
```

### Scanner panel shows "not run" in the dashboard

The panels read `state/sast_report.json` / `state/dast_report.json`. Run a scan
(`--with-sast` / `--mode sast-only`) or check that the file exists on disk.

---

## Performance & Port Sharing Note

- When you run `python vulnapp/app.py` inside WSL on port `5000`, WSL2 forwards `localhost:5000` to Windows automatically.
- You can even run `vulnapp/app.py` in WSL and run `main.py` from Windows PowerShell (or vice versa)!
