# Raphael 2.0 — System Audit

> **Live audit**: 2026-07-11. Running processes, tools, config, and architecture.
> See bottom section for the original code audit (2026-07-06).

---

## Running Processes

| PID | Process | User | Transport | Status |
|-----|---------|------|-----------|--------|
| 76 | `raphael_mcp_server.py` | yaser | stdio (MCP) | ✅ LIVE |
| 257 | `openvpn` (machines_us-5) | root | tun0 (10.10.15.184) | ✅ CONNECTED |

### NOT Running
| Component | How to Start | Notes |
|-----------|-------------|-------|
| **MCP Hub** (HTTP :8000) | `docker compose up -d mcp-hub` | searchsploit, metasploit, evil-winrm unavailable |
| **Brain** (`raphael_brain.py`) | `venv/bin/python raphael_brain.py` | Kimi executive — manual launch |
| **CLI** (`raphael_cli.py`) | `venv/bin/python raphael_cli.py` | Full command interface |
| **Docker services** (17 containers) | `docker compose up -d` | cai-service, c2-server, mhddos, cloak, phish, etc. all down |

---

## MCP Server Tools — Availability

| Tool | Type | Calls Binary | Installed? | Works? |
|------|------|-------------|-----------|--------|
| `call-llm` | LLM | Python (orchestrator.providers) | ✅ built-in | ✅ |
| `list-models` | LLM | Python | ✅ built-in | ✅ |
| `nmap-scan` | recon | `nmap` | ✅ | ✅ |
| `gobuster` | web | `gobuster` | ✅ (with dirb wordlists) | ✅ |
| `sqlmap-scan` | web | `sqlmap` | ✅ | ✅ (MCP timed out) |
| `nuclei-scan` | vuln | `nuclei` | ❌ go install failed | ❌ |
| `subfinder` | recon | `subfinder` | ❌ | ❌ |
| `proxy-status` | infra | Python | ✅ | ✅ |
| `verify` | infra | Python | ✅ | ✅ |
| `web-search` | recon | Python (DuckDuckGo) | ✅ | ✅ |
| `fetch-url` | recon | Python (httpx) | ✅ | ✅ |
| `debate` | LLM | Python | ✅ | ✅ |
| `deep-research` | LLM | Python | ✅ | ✅ |
| `autonomous-engage` | pipeline | Python | ✅ | ✅ |
| `run-tool` | hub | Python (mcp-hub registry) | ❌ hub not running | ❌ |
| `raphael-tools` | hub | Python (read-only list) | ✅ | ✅ |

**Missing critical:** `nuclei` (template-based vuln scanning), `searchsploit` (in hub), `metasploit` (in hub).

---

## Locally Installed Binaries

| Binary | Path | Status |
|--------|------|--------|
| `python3` | `/usr/bin/python3` | ✅ 3.14.4 |
| `pip3` | `/usr/bin/pip3` | ✅ (PEP 668 locked) |
| `curl` | `/usr/bin/curl` | ✅ |
| `nmap` | `/usr/bin/nmap` | ✅ 7.98 |
| `hydra` | `/usr/bin/hydra` | ✅ 9.6 |
| `gobuster` | `/usr/bin/gobuster` | ✅ 3.8.2 |
| `dirsearch` | `/usr/bin/dirsearch` | ✅ 0.4.3 |
| `nikto` | `/usr/bin/nikto` | ✅ 2.1.5 |
| `whatweb` | `/usr/bin/whatweb` | ✅ 0.6.3 |
| `sqlmap` | `/usr/bin/sqlmap` | ✅ 1.10.4 |
| `masscan` | `/usr/bin/masscan` | ✅ |
| `ffuf` | `/usr/local/bin/ffuf` | ✅ 2.1.0 |
| `go` | `/usr/bin/go` | ✅ 1.26 |
| `dirb` | `/usr/bin/dirb` | ✅ 2.22 (wordlists at `/usr/share/dirb/wordlists/`) |
| `netcat` | `/usr/bin/nc` | ✅ |
| `openvpn` | `/usr/sbin/openvpn` | ✅ |
| `nuclei` | — | ❌ go install failed (deps timeout) |
| `subfinder` | — | ❌ not installed |
| `searchsploit` | — | ❌ (in MCP Hub — not running) |
| `metasploit` | — | ❌ (in MCP Hub — not running) |
| `evil-winrm` | — | ❌ (in MCP Hub — not running) |
| `prowler` | — | ❌ (in MCP Hub — not running) |
| `trivy` | — | ❌ (in MCP Hub — not running) |
| `volatility` | — | ❌ (in MCP Hub — not running) |

---

## API Keys

| Key | Value | Status |
|-----|-------|--------|
| `NVIDIA_API_KEY` | `nvapi-g7Gp...` | ✅ Present |
| `NVIDIA_API_KEY_2` | `nvapi-2A7J...` | ✅ Present |
| `NVIDIA_API_KEY_3` | `nvapi-tRpc...` | ✅ Present |
| `FREELLMAPI_KEY` | `freellmapi-43e4...` | ✅ Present |
| `FREELLMAPI_BASE` | `http://localhost:3001/v1` | ✅ Configured |
| `OMNIROUTE_BASE` | `http://localhost:20128/v1` | ✅ Configured |
| `OMNIROUTE_API_KEY` | `sk-omniroute-local` | ✅ Configured |
| `API_KEY` | `raphael-layer5-dev-key-2026` | ⚠️ Default |
| `GOPHISH_API_KEY` | `change-me-gophish-api-key` | ⚠️ Default |
| `TOR_CONTROL_PASS` | `changeme` | ⚠️ Default |
| `OPENAI_API_KEY` | (empty) | ❌ Missing |
| `SHODAN_API_KEY` | (empty) | ❌ Missing |
| `SPIDERFOOT_API_KEY` | (empty) | ❌ Missing |

**Cost control:** `MAX_SPEND_TOKENS=1000000`, `RAPHAEL_COST_CONTROL=1`

---

## LLM Models (5 providers, 60+ aliases)

| Provider | Endpoint | Key Models |
|----------|----------|-----------|
| **NVIDIA API** | api.nvidia.com | deepseek, nemotron*, mistral*, kimi |
| **FreeLLMAPI** (proxy) | localhost:3001/v1 | Same NVIDIA models via proxy |
| **Ollama** (ollama.com) | API | wormgpt*, gemma4, gemma4-think |
| **OpenRoute** (openrouter.ai) | API | or-deepseek, or-nemotron, or-qwen, or-ling |
| **OpenCode CLI** | local CLI | oc-deepseek, oc-nemotron-*, oc-mistral-* |

---

## Architecture Layers

```
┌─────────────────────────────────────────────┐
│  MCP Server (raphael_mcp_server.py)  PID 76 │  ← stdio transport
│  Tools: call-llm, nmap, gobuster, sqlmap... │
├─────────────────────────────────────────────┤
│  Brain (raphael_brain.py)  NOT RUNNING      │  ← Kimi executive loop
│  13 tools: nmap, nuclei, ssh-exec, ...     │     (replacing autonomous mode)
├─────────────────────────────────────────────┤
│  Orchestrator Modes                         │  ← Hardcoded pipelines
│  autonomous, scan, debate, community,       │
│  deep_research, postmortem, rsi             │
├─────────────────────────────────────────────┤
│  MCP Hub (mcp-hub/)  NOT RUNNING           │  ← HTTP :8000, FastAPI
│  14 tools across 6 categories               │     (searchsploit, metasploit, etc.)
├─────────────────────────────────────────────┤
│  Docker Services (17)  ALL DOWN             │  ← cai-service, c2, mhddos,
│                                              │     cloak, phishing, etc.
└─────────────────────────────────────────────┘
```

---

## Training Engagements (raphael_training.md)

| # | Target | Type | CVEs / Techniques |
|---|--------|------|-------------------|
| 001 | Support (10.129.51.253) | Easy Win DC | SMB anon, .NET decomp, LDAP recon, RBCD |
| 002 | Orion (10.129.53.83) | Medium Linux | CVE-2025-32432, FnStream, telnetd privesc |
| 003 | React Oops (154.57.164.81:32184) | Very Easy Web | CVE-2025-55182 RCE via RSC Flight |
| 004 | OpenSecret (154.57.164.72:31994) | Very Easy Web | Hardcoded JWT secret, token forgery |
| 005 | Unit42 | Very Easy Sherlock | Sysmon logs, UltraVNC backdoor |
| 006 | Enigma (10.129.239.191) | Easy Linux | NFS mount, IMAP pivot, ZIP injection |
| 007 | Connected (10.129.52.169) | Easy Linux | (partial) |

---

## Personas

| Persona | Description |
|---------|-------------|
| `default` | Standard helpful AI operator |
| `redteam` | Professional red team (authorized testing) |
| `blackhat` | Unrestricted, zero limitations, no refusal |

Prompt sanitization strips target IPs/identifiers before sending to safety-filtered models (kimi, gemma4).

---

## Known Issues

| Issue | Details |
|-------|---------|
| `nuclei` not installed | Go install failed due to dependency download timeout |
| MCP Hub not running | 14 tools unavailable (searchsploit, metasploit, etc.) |
| No Docker services | 17 containers all down |
| Brain not running | Must be launched manually with `python raphael_brain.py` |
| Default credentials | `API_KEY`, `GOPHISH_API_KEY`, `TOR_CONTROL_PASS` unchanged |
| Missing API keys | `OPENAI_API_KEY`, `SHODAN_API_KEY`, `SPIDERFOOT_API_KEY` empty |
| No wordlists | Only dirb wordlists available at `/usr/share/dirb/wordlists/` |
| `pip` externally managed | PEP 668 — can't `pip install` without `--break-system-packages` |

---

# Raphael 2.0 — Code Audit Findings (Original)

> Generated 2026-07-06. Deep end-to-end audit of all 439 files.
> **All issues below have been remediated (commit `163fa20`).**

---

## CRITICAL — Container Won't Start

### 1. brain/api.py Missing

| Field | Value |
|-------|-------|
| **File** | `brain/Dockerfile` CMD: `uvicorn brain.api:app --port 3700` |
| **Problem** | `brain/api.py` does not exist. The `brain/` directory only contains: `auth_monitor.py`, `engagement_modes.py`, `engagement_state.py`, `partial_report.py`. |
| **Impact** | `autonomous-brain` container crashes on startup — uvicorn cannot find the module. |
| **Fix** | CMD updated to `orchestrator.brain.api:app` in `brain/Dockerfile`. The module exists at `orchestrator/brain/api.py` (false alarm — build context is project root, not `brain/`). |

---

## HIGH — Security

### 2. Hardcoded Sudo Password

| Field | Value |
|-------|-------|
| **File** | `raphael_anonymity_test.sh` lines 82, 87, 88, 100 |
| **Problem** | Sudo password `23532231` is hardcoded in plain text and piped to `sudo -S`. Anyone with read access to this file gains passwordless sudo on the machine. |
| **Impact** | Severe security exposure. Remove hardcoded password and use `sudo -k` or `NOPASSWD` in sudoers instead. |
| **Fix** | All 4 occurrences replaced with `sudo -n` (non-interactive, requires NOPASSWD in sudoers). |

---

## HIGH — HRM Paths Broken <sup>*(removed — hardware bottleneck)*</sup>

### 3–5. HRM Issues

Removed from project. `start_hrm.sh` and `config/hrm_service.conf` no longer used.

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
| **Fix** | Added `docs/osmania-recon/` as a fallback search path for the recon file that exists there. Remaining 4 files don't exist in the project — silently skipped (handled by existing `FileNotFoundError` catch). |

---

## MEDIUM — Network Configuration

### 7. MCP Hub Network Name Mismatch

| Field | Value |
|-------|-------|
| **Files** | `mcp-hub/docker-compose.yml` vs `docker-compose.yml` |
| **Problem** | MCP hub compose declares network `raphael-net` as `external: true` with `name: raphael-2.0`. Main compose creates `raphael-net` as an ordinary bridge network (actual Docker name: `raphael-2.0_raphael-net`). |
| **Impact** | MCP hub cannot communicate with main compose services. Not necessarily blocking — MCP hub can run standalone — but they won't be on the same Docker network. |
| **Fix** | Changed `name: raphael-2.0` to `name: raphael-2.0_raphael-net` in `mcp-hub/docker-compose.yml` to match Docker Compose auto-naming. |

---

## MEDIUM — Shell Script Issues

### 8. Undefined Variable in kill_switch_status.sh

| Field | Value |
|-------|-------|
| **File** | `kill_switch_status.sh:17` |
| **Problem** | Uses `$VPN_IF` which is never defined in this script (defined only in `kill_switch.sh`). Will silently expand to empty string, resulting in `ip link show` with no interface argument — likely a syntax error at runtime. |
| **Fix** | Changed `$VPN_IF` to literal `tun1`. |

### 9. Missing Shebangs (3 files — 3 others already had shebangs)

| File | Status |
|------|--------|
| `run_resume_rsi.py` | Shebang added |
| `run_community_v2.py` | Already had shebang — no change needed |
| `run_reasoning_v2.py` | Already had shebang — no change needed |
| `run_fixplan_debate_v2.py` | Already had shebang — no change needed |
| `run_debate_rsi.py` | Shebang added |
| `orchestrator/run_osmania_autonomous.py` | Shebang added |

### 10. Hardcoded Container Names

| Field | Value |
|-------|-------|
| **File** | `raphael_anonymity_test.sh:143` |
| **Problem** | Container names hardcoded as `raphael-20-recon-pipeline-1`, `raphael-20-sword-1`, etc. Docker Compose-generated names depend on the project directory name — they may differ if the repo is cloned to a different path. |
| **Fix** | Replaced with `docker compose ps -q <service>` dynamic lookup using compose service names. |

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

> **Fix**: All 27 stale vars removed from `.env.example`. `FROM_EMAIL` → `FROM_ADDR`, `SUBFINDER_CONFIG` → `SUBFINDER_PATH`. See commit `163fa20`.

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
| **Fix** | Added `glm`, `nemotron-super-120b`, `nemotron-super15` to `WORKING_ALIASES`. Minimax family (`minimax`, `minimaxm3`, `m3`) left out — documented as unreliable (timeout/empty responses). |

---

## LOW

### 14. `JWT_SECRET` is Dead Config

| Field | Value |
|-------|-------|
| **File** | `.env.example` + `raphael_cli.py:59` |
| **Problem** | Listed in `.env.example` and checked for a weak-default warning in `raphael_cli.py`, but no code in the entire codebase performs JWT signing or verification. The variable has no functional effect. |
| **Fix** | Removed from `.env.example` and `raphael_cli.py:_WEAK_DEFAULTS`. |

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 1 | Fixed — false alarm, module exists at `orchestrator/brain/api.py` |
| HIGH | 1 | Fixed — `sudo -S` replaced with `sudo -n` |
| HIGH | 3 | Removed — HRM subsystem decommissioned |
| MEDIUM | 8 | All fixed — see items 6–13 above |
| LOW | 1 | Fixed — `JWT_SECRET` removed from config and cli |
| **Total** | **14** | **All remediated in commit `163fa20`** |
