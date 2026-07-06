# Raphael 2.0 — Audit Findings

> Generated 2026-07-06. Deep end-to-end audit of all 439 files.
> **Issues are documented only. No fixes have been applied.**

---

## CRITICAL — Container Won't Start

### 1. brain/api.py Missing

| Field | Value |
|-------|-------|
| **File** | `brain/Dockerfile` CMD: `uvicorn brain.api:app --port 3700` |
| **Problem** | `brain/api.py` does not exist. The `brain/` directory only contains: `auth_monitor.py`, `engagement_modes.py`, `engagement_state.py`, `partial_report.py`. |
| **Impact** | `autonomous-brain` container crashes on startup — uvicorn cannot find the module. |
| **Fix needed** | Create `brain/api.py` with a FastAPI `app` instance, or change the Dockerfile CMD to reference an existing module. |

---

## HIGH — Security

### 2. Hardcoded Sudo Password

| Field | Value |
|-------|-------|
| **File** | `raphael_anonymity_test.sh` lines 82, 87, 88, 100 |
| **Problem** | Sudo password `23532231` is hardcoded in plain text and piped to `sudo -S`. Anyone with read access to this file gains passwordless sudo on the machine. |
| **Impact** | Severe security exposure. Remove hardcoded password and use `sudo -k` or `NOPASSWD` in sudoers instead. |

---

## HIGH — HRM Paths Broken

### 3. HRM venv Path Wrong

| Field | Value |
|-------|-------|
| **File** | `start_hrm.sh:5` |
| **Problem** | References `/home/yaser/Ultimate skill/HRM/.venv/bin/python` — this path does not exist. The actual HRM code is at `/home/yaser/Ultimate skill/HRM(FUTURE)/HRM/HRM/`. |
| **Impact** | `start_hrm.sh` fails immediately with "HRM venv not found". |

### 4. HRM Module Not Found

| Field | Value |
|-------|-------|
| **File** | `start_hrm.sh:18` |
| **Problem** | References `orchestrator.hrm_service` — no `hrm_service.py` exists in the main `orchestrator/` directory. |
| **Impact** | Even if the venv path were fixed, the module import would fail. |

### 5. Supervisor Config Broken

| Field | Value |
|-------|-------|
| **File** | `config/hrm_service.conf` |
| **Problem** | References same non-existent paths as `start_hrm.sh`: Python binary and `orchestrator.hrm_service` module. |
| **Impact** | Supervisor can't start HRM service. |

---

## MEDIUM — Data Files Missing

### 6. Osmania Autonomous Script Missing Data Files

| Field | Value |
|-------|-------|
| **File** | `orchestrator/run_osmania_autonomous.py` |
| **Problem** | Expects 5 files in `data/` that don't exist: |
| | `data/phase0-live-recon-results.txt` — not found anywhere in project |
| | `data/recon-test-osmania-2026-06-26.txt` — exists at `docs/osmania-recon/` instead |
| | `data/OSMANIA_TARGET_REPORT.md` — not found anywhere |
| | `data/SWORD.md` — not found anywhere |
| | `data/PROGRESS.md` — not found anywhere |
| **Impact** | Script will fail with `FileNotFoundError` when attempting to read these files. |

---

## MEDIUM — Network Configuration

### 7. MCP Hub Network Name Mismatch

| Field | Value |
|-------|-------|
| **Files** | `mcp-hub/docker-compose.yml` vs `docker-compose.yml` |
| **Problem** | MCP hub compose declares network `raphael-net` as `external: true` with `name: raphael-2.0`. Main compose creates `raphael-net` as an ordinary bridge network (actual Docker name: `raphael-2.0_raphael-net`). |
| **Impact** | MCP hub cannot communicate with main compose services. Not necessarily blocking — MCP hub can run standalone — but they won't be on the same Docker network. |

---

## MEDIUM — Shell Script Issues

### 8. Undefined Variable in kill_switch_status.sh

| Field | Value |
|-------|-------|
| **File** | `kill_switch_status.sh:17` |
| **Problem** | Uses `$VPN_IF` which is never defined in this script (defined only in `kill_switch.sh`). Will silently expand to empty string, resulting in `ip link show` with no interface argument — likely a syntax error at runtime. |

### 9. Missing Shebangs (6 files)

| File | Problem |
|------|---------|
| `run_resume_rsi.py` | No `#!/usr/bin/env python3` shebang |
| `run_community_v2.py` | No shebang |
| `run_reasoning_v2.py` | No shebang |
| `run_fixplan_debate_v2.py` | No shebang |
| `run_debate_rsi.py` | No shebang |
| `orchestrator/run_osmania_autonomous.py` | No shebang |

### 10. Hardcoded Container Names

| Field | Value |
|-------|-------|
| **File** | `raphael_anonymity_test.sh:143` |
| **Problem** | Container names hardcoded as `raphael-20-recon-pipeline-1`, `raphael-20-sword-1`, etc. Docker Compose-generated names depend on the project directory name — they may differ if the repo is cloned to a different path. |

---

## MEDIUM — Environment Variable Drift

### 11. `.env.example` is 56% Stale

27 of 48 vars in `.env.example` are not read by any running code. These are Raphael 1.x leftovers that were never removed:

| Stale Var | Category |
|-----------|----------|
| `JWT_SECRET` | Auth — no code signs or verifies JWTs |
| `MHDDOS_THREADS` | MHDDoS — not read by any .py |
| `MHDDOS_DEFAULT_METHOD` | MHDDoS — not read by any .py |
| `GOPHISH_API_HOST` | Phishing — not read by any .py |
| `GOPHISH_API_PORT` | Phishing — not read by any .py |
| `C2_LISTENER_PORT` | C2 — not read by any .py |
| `PUPPY_LISTENER` | C2 — not read by any .py |
| `WINRM_USER` | C2 — not read by any .py |
| `WINRM_PASS` | C2 — not read by any .py |
| `WINRM_PORT` | C2 — not read by any .py |
| `SUBFINDER_CONFIG` | Recon — code reads `SUBFINDER_PATH` (different var) |
| `NEO4J_URI` | Neo4j — not read by any .py |
| `PROXY_STRATEGY` | Proxy — not read by any .py |
| `PROTONVPN_SERVICE_CHECK` | Proxy — not read |
| `ACADEMIC_JUMPS` | Proxy — not read |
| `SSH_KEY_PATH` | Proxy — not read |
| `CHAIN_ORDER` | Proxy — not read |
| `AUTO_CLEANUP` | Anti-forensics — not read |
| `DEFAULT_PLATFORM` | Anti-forensics — not read |
| `CLEANUP_LEVEL` | Anti-forensics — not read |
| `MIMICRY_TZ` | Mimicry — not read |
| `MIMICRY_VELOCITY` | Mimicry — not read |
| `MIMICRY_BUSINESS_HOURS_START` | Mimicry — not read |
| `MIMICRY_BUSINESS_HOURS_END` | Mimicry — not read |
| `MIMICRY_DAYS` | Mimicry — not read |
| `OPENAI_MODEL` | Model — was used in Raphael 1.x, removed in 2.0 |
| `FROM_EMAIL` | Phishing — code reads `FROM_ADDR` (different name) |

### 12. ~42 Env Vars Undocumented

Code reads ~42 environment variables that have no entry in `.env.example`. See `SETUP_GUIDE.md §2.3` for the full list. Notable gaps:

- `TOR_CONTROL_PASS` — Tor auth (`.env.example` has `TOR_PASSWORD` — different name for same concept)
- `FROM_ADDR` — Sender email (`.env.example` has `FROM_EMAIL` — different name)
- `SUBFINDER_PATH` — Binary path (`.env.example` has `SUBFINDER_CONFIG` — different meaning)
- `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` — Telegram MCP credentials
- `C2_PSK`, `C2_TASK_DIR`, `C2_URL`, `AGENT_ID` — C2 configuration

### 13. `WORKING_ALIASES` Out of Sync

| Field | Value |
|-------|-------|
| **File** | `orchestrator/providers.py:98-104` |
| **Problem** | `WORKING_ALIASES` omits: `glm`, `nemotron-super-120b`, `nemotron-super15`, `minimax`, `minimaxm3`, `m3`. However, `m3` is explicitly used by `call_parallel()` on line 351. When `call_model("m3", ...)` is called, the `model not in WORKING_ALIASES` check on line 297 triggers the auto-pick path instead of using `m3`. |

---

## LOW

### 14. `JWT_SECRET` is Dead Config

| Field | Value |
|-------|-------|
| **File** | `.env.example` + `raphael_cli.py:59` |
| **Problem** | Listed in `.env.example` and checked for a weak-default warning in `raphael_cli.py`, but no code in the entire codebase performs JWT signing or verification. The variable has no functional effect. |

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| CRITICAL | 1 | `brain/api.py` missing — container won't start |
| HIGH | 4 | Hardcoded sudo password, HRM paths broken (3 issues) |
| MEDIUM | 8 | Missing data files, network mismatch, shell bugs, env var drift, `WORKING_ALIASES` out of sync |
| LOW | 1 | Dead `JWT_SECRET` config |
| **Total** | **14** | |
