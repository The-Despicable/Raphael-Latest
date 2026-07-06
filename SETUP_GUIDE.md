# Raphael 2.0 — Setup Guide

> **Format recovery document.** Everything needed to rebuild from a bare WSL/Ubuntu system.

---

## 1. Directory Structure

```
raphael-2.0/                          # Project root (git repo root)
│
├── .env.example                      # Template — copy to .env, fill keys
├── .gitignore
├── bootstrap.sh                      # Full auto-setup (deps, venv, docker build)
├── requirements.txt                  # Host-side Python dependencies
├── QUICKSTART.md                     # Quick <30-min rebuild reference
├── SETUP_GUIDE.md                    # THIS FILE — full setup & audit
├── procedure.md                      # Mandatory OPSEC pre-flight protocol
├── ghost.md                          # Invisibility / anti-detection reference
├── FAILURE_MODES.md                  # Log of recurring failure patterns
├── HRM.md                            # Hierarchical Reasoning Model research
│
├── docker-compose.yml                # Main orchestration (9 platform services)
├── Dockerfile.sandbox                # Sandbox container for tool execution
│
├── orchestrator/                     # Core orchestration engine
│   ├── app.py                        # CLI entry point (all modes)
│   ├── providers.py                  # Model routing (22 aliases, 5 categories)
│   ├── proxy_guard.py                # Tor/proxy enforcement
│   ├── teams.py                      # Team workflows (debate/analyze/code/execute)
│   ├── critic.py                     # Post-execution failure detector
│   ├── code_verifier.py              # Rejects non-existent endpoint references
│   ├── adaptive_router.py            # Task classification & model selection
│   ├── conductor.py                  # Multi-model task conductor
│   ├── anti_forensics.py             # Platform-specific cleanup
│   ├── rag_knowledge.py              # RAG context for endpoint data
│   ├── audit_trail.py                # Audit logging
│   ├── c2_channel.py                 # C2 communication channel
│   ├── hexstrike_wrapper.py           # HexStrike MCP bridge
│   ├── spiderfoot_wrapper.py          # SpiderFoot OSINT wrapper
│   ├── karma_wrapper.py               # karma_v2 passive recon wrapper
│   ├── skills_bridge.py               # Skills integration bridge
│   ├── claude_analysis.py             # Claude analysis runner
│   ├── community_implement.py         # Community mode impl generator
│   │
│   ├── modes/                        # Execution modes (one per file)
│   │   ├── __init__.py
│   │   ├── debate.py
│   │   ├── community.py
│   │   ├── rsi.py
│   │   ├── scan.py                   # Network scanning
│   │   ├── autonomous.py             # Full autonomous engagement
│   │   ├── deep_research.py          # Web research pipeline
│   │   └── postmortem.py             # Failure analysis
│   │
│   ├── brain/                        # Adaptive model selection & memory
│   │   ├── adaptive_brain.py         # Thompson sampling / PSO model selector
│   │   ├── neural_memory.py          # Episodic + semantic memory
│   │   ├── target_profiler.py        # Target classification
│   │   ├── target_state.py           # Target state tracking
│   │   ├── anonymity_guard.py        # Anonymity enforcement
│   │   ├── api.py                    # Brain API (port 3700)
│   │   ├── autonomous.py             # Brain-driven autonomous orchestration
│   │   ├── schema_registry.py        # Memory schema definitions
│   │   ├── skill_indexer.py          # Skill indexing for retrieval
│   │   ├── auth_monitor.py           # Authentication monitoring
│   │   ├── engagement_modes.py       # Engagement mode definitions
│   │   ├── engagement_state.py       # Engagement state management
│   │   └── partial_report.py         # Partial report generation
│   │
│   ├── agents/                       # CAI agent implementations
│   │   ├── __init__.py
│   │   └── skill_agent.py
│   │
│   ├── scanners/                     # Network scanning wrappers
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── nmap_scanner.py
│   │   ├── nuclei_scanner.py
│   │   └── whatweb_scanner.py
│   │
│   ├── exploit/                      # Exploitation pipeline
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── sqlmap_wrapper.py
│   │   ├── mcp_bridge.py             # MCP tool bridge
│   │   ├── payloads_db.py            # Payload database
│   │   ├── nettacker_exploit.py
│   │   ├── ssrf_scanner.py
│   │   └── xss_scanner.py
│   │
│   ├── postex/                       # Post-exploitation
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── pupy_c2.py
│   │   ├── winrm_exploit.py
│   │   ├── netexec_wrapper.py
│   │   ├── ladon_scanner.py
│   │   └── bloodhound_integration.py
│   │
│   ├── exfil/                        # Data exfiltration
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── dns_tunnel.py
│   │   ├── smtp_tunnel.py
│   │   ├── bounceback.py
│   │   ├── redcloud.py
│   │   └── bulk_exfil.py
│   │
│   ├── phishing/                     # Phishing operations
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── gophish.py
│   │   ├── evilginx.py
│   │   └── set_wrapper.py
│   │
│   ├── sast/                         # SAST pipeline
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── adaptive_router.py
│   │   ├── pattern_engine.py
│   │   ├── llm_analyzer.py
│   │   └── report_generator.py
│   │
│   ├── runtime/                      # Runtime session management
│   │   ├── __init__.py
│   │   ├── session_manager.py
│   │   ├── docker_client.py
│   │   └── caido_bootstrap.py
│   │
│   └── utils/                        # Utility modules
│   │   ├── __init__.py
│   │   ├── undercover.py             # Text normalization (strip AI markers)
│   │   └── retry.py                  # Exponential backoff + fallback chain
│   │
│   ├── data/                         # Runtime data (gitignored — not in repo)
│   └── db/                           # Database files (gitignored — not in repo)
│
├── sword/                            # 6-phase engagement pipeline
│   ├── Dockerfile
│   ├── api.py                        # FastAPI on port 3600
│   ├── pipeline.py                   # Pipeline orchestration
│   ├── report.py                     # Report generation
│   ├── phase_0_recon.py
│   ├── phase_1_scan.py
│   ├── phase_2_exploit.py
│   ├── phase_3_postex.py
│   ├── phase_4_exfil.py
│   ├── phase_5_phish.py
│   └── requirements.txt
│
├── cai-service/                      # CAI agent microservice (:3200)
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
│
├── mhddos-service/                   # DDoS stress-test (:3300)
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
│
├── cloak-service/                    # Playwright browser automation (:3400)
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
│
├── c2-server/                        # C2 operations (:3501)
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
│
├── phishing/                         # Phishing campaigns (:3502)
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
│
├── recon-pipeline/                   # Recon pipeline (:3503)
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── schema.sql
│   ├── case_store.py
│   ├── case_api.py
│   ├── stale_recovery.py
│   └── producers/
│       └── recon_ingest.py
│
├── brain/                            # Brain Docker build context
│   ├── Dockerfile
│   ├── auth_monitor.py
│   ├── engagement_modes.py
│   ├── engagement_state.py
│   └── partial_report.py
│
├── mcp-hub/                          # MCP tool server (:8000)
│   ├── docker-compose.yml            # Standalone compose
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── config.yaml
│   ├── core/
│   │   ├── server.py                 # MCP server
│   │   ├── registry.py               # Tool registry (auto-load)
│   │   ├── decision_engine.py        # Recommends tool chains
│   │   ├── auth.py
│   │   ├── security.py
│   │   └── transport.py
│   ├── schemas/
│   │   ├── tools.py                  # Pydantic models
│   │   └── mcp.py
│   ├── tools/                        # Tool implementations
│   │   ├── recon/   (nmap, subfinder)
│   │   ├── exploit/ (metasploit)
│   │   ├── web/     (nuclei, sqlmap, gobuster)
│   │   ├── c2/      (pupy)
│   │   ├── cloud/   (prowler)
│   │   ├── forensics/ (volatility)
│   │   └── phishing/ (gophish)
│   ├── static/
│   │   └── tool-registry.json
│   └── tests/
│
├── exploits/                         # Exploit scripts
│   ├── exploit_all.py
│   ├── exploit_sqli_login.py
│   ├── exploit_sqli_search.py
│   ├── exploit_ghostcat.py
│   ├── exploit_idor.py
│   ├── exploit_lfi.py
│   ├── exploit_jsp_sqli.py
│   ├── exploit_mass_assignment.py
│   ├── exploit_upload_webshell.py
│   ├── vulnu_harness.py
│   └── *.json                        # Result files
│
├── config/                           # Config files
│   └── hrm_service.conf              # Supervisor config for HRM (BROKEN — see §5)
│
├── references/                       # Security reference library
│   ├── INDEX.md
│   ├── handoff-protocols.md
│   ├── wildcard-mode.md
│   ├── vuln-checklists/   (10 OWASP Top 10 checklists)
│   ├── api-security/      (10 API security references)
│   ├── payloads/          (20 payload type references)
│   ├── tools/             (10 tool usage guides)
│   ├── active-directory/  (4 AD attack references)
│   └── offensive-tactics/ (18 tactic references)
│
├── telegram mcp/                     # Telegram MCP integration
│   ├── setup.sh
│   ├── .env.example
│   ├── mcp_server.py
│   ├── telegram_bot.py
│   ├── opencode.json
│   └── requirements.txt
│
├── templates/                        # Report templates
├── static/                           # Static assets
│
├── docs/                             # External docs moved into repo
│   ├── raphael-2.0-blueprint.md      # Architecture blueprint
│   ├── MASTER_REPORT.md              # Master end-to-end analysis
│   ├── osmania_target_prompt.md
│   ├── osmania-lab-spec.md
│   ├── deep-research/                # Deep research outputs (7 files)
│   ├── stitch-screens/               # UI design screens (4 HTML + 4 PNG)
│   ├── worm-judgments/               # Worm model judgment files (4 files)
│   └── osmania-recon/                # Osmania recon test outputs (2 files)
│
├── *.sh                              # Setup & utility scripts
│   ├── bootstrap.sh                  # Full auto-setup
│   ├── setup_anon.sh                 # Deploy anonymous layer (Tor + dnscrypt)
│   ├── setup_killswitch.sh           # iptables kill switch
│   ├── kill_switch.sh                # iptables rules
│   ├── kill_switch_disable.sh
│   ├── kill_switch_status.sh
│   ├── start_hrm.sh                  # HRM microservice launcher
│   └── raphael_anonymity_test.sh     # Anonymity test suite
│
├── run_*.py                          # Run scripts for various modes (14 files)
└── *.json                            # Run outputs and configuration files
```

### Key Ports

| Service | Internal | External (compose) | Purpose |
|---------|----------|-------------------|---------|
| cai-service | 3200 | 3201 | AI agent API |
| mhddos-service | 3300 | 3301 | DDoS stress-test |
| cloak-service | 3400 | 3401 | Playwright browser automation |
| c2-server | 3501 | 3501 | C2 operations |
| phishing | 3502 | 3502 | GoPhish campaigns |
| recon-pipeline | 3503 | 3503 | Recon pipeline |
| sword | 3600 | 3600 | Engagement pipeline |
| autonomous-brain | 3700 | 3700 | Brain API |
| tor-proxy | 9050/9051 | 9050/9052 | Tor SOCKS + Control |
| neo4j | 7687/7474 | 7687/7474 | Graph database |
| caido | 8080 | 48080 | Web proxy |
| mcp-hub | 8000 | 8000 | MCP tool server (standalone) |
| ollama | 11434 | — | Local LLM proxy (host) |
| tor (host) | 9050/9051 | — | Host Tor daemon |

---

## 2. Environment Configuration

### 2.1 `.env` Setup

```bash
cp .env.example .env
# Edit .env with your keys:
nano .env
```

**Minimum required keys** (at least one API provider):

| Variable | Required | Provider | How to Get |
|----------|----------|----------|------------|
| `NVIDIA_API_KEY` | Yes* | NVIDIA build.nvidia.com | Sign up at build.nvidia.com → API Keys |
| `OPENAI_API_KEY` | Yes* | OpenAI / OpenRouter | platform.openai.com |
| `OMNIROUTE_API_KEY` | No | OmniRoute (local proxy) | Run OmniRoute on localhost:20128 |

\* At least one of `NVIDIA_API_KEY` or `OPENAI_API_KEY` is required.

### 2.2 Model Inventory (`orchestrator/providers.py`)

**22 model aliases across 5 categories:**

| Category | Provider | Aliases |
|----------|----------|---------|
| **Code Gen** | NVIDIA API | `deepseek`, `glm`, `nemotron`, `nemotron-super-120b`, `mistral-small` |
| **Reasoning** | NVIDIA API | `kimi`, `nemotron-super`, `nemotron-super15`, `mistral-large`, `mistral-medium`, `nemotron-nano-reasoning`, `mistral-nemotron` |
| **Offensive** | Ollama → ollama.com | `wormgpt`, `wormgpt12`, `wormgpt13`, `wormgpt480b`, `w12`, `w13`, `w480b` |
| **Fast Reasoning** | Ollama → ollama.com | `minimax`, `minimaxm3`, `m3`, `gemma4`, `gemma4-think` |
| **OmniRoute Fallback** | OmniRoute (local) | `or-deepseek`, `or-nemotron`, `or-minimax`, `or-qwen`, `or-ling` |

**Routing logic** (`providers.py:233`):
- NVIDIA aliases → NVIDIA API (`integrate.api.nvidia.com/v1`)
- Ollama aliases → local Ollama (`localhost:11434/v1`), which proxies to ollama.com
- OmniRoute fallbacks → local OmniRoute (`localhost:20128/v1`)

### 2.3 Env Vars Read by Code vs `.env.example`

**Vars in `.env.example` that ARE actually read:**

| Var | Read By |
|-----|---------|
| `NVIDIA_API_KEY` | `providers.py:15` |
| `OPENAI_API_KEY` | `providers.py:14` |
| `OMNIROUTE_BASE` | `providers.py:16` |
| `OMNIROUTE_API_KEY` | `providers.py:17` |
| `MAX_SPEND_TOKENS` | `providers.py:79` |
| `RAPHAEL_COST_CONTROL` | `providers.py:80` |
| `TOR_PROXY` | `cloak-service/main.py:19`, `mhddos-service/main.py:81` |
| `TOR_CONTROL` | `cloak-service/main.py:20`, `brain/anonymity_guard.py:44` |
| `TOR_PASSWORD` | `cloak-service/main.py:21` |
| `API_KEY` | `app.py:146`, `sast/pipeline.py:8` |
| `GOPHISH_API_KEY` | `phishing/gophish.py:6` |
| `SHODAN_API_KEY` | `sword/phase_0_recon.py:70`, `karma_wrapper.py:11` |
| `SPIDERFOOT_API_KEY` | `sword/api.py:37` |
| `OPENAI_BASE_URL` | `providers.py:13` |

**Vars read by code but MISSING from `.env.example` (42 vars):**

| Var | Where Read | Purpose |
|-----|-----------|---------|
| `TOR_CONTROL_HOST` | `mhddos-service/main.py:82` | Tor control hostname |
| `TOR_CONTROL_PORT` | `mhddos-service/main.py:83` | Tor control port |
| `TOR_CONTROL_PASS` | `brain/anonymity_guard.py:45` | Tor auth (different from `TOR_PASSWORD`) |
| `PORT` | `cloak-service/main.py:22` | HTTP listen port |
| `RAPHAEL_PATH` | `mhddos-service/main.py:11` | Project root path |
| `MHDPATH` | `mhddos-service/main.py:80` | MHDDoS script path |
| `MHDDOS_PYTHON` | `mhddos-service/main.py:84` | Python interpreter |
| `HOST` | `mhddos-service/main.py:85` | HTTP bind host |
| `SMTP_USER` | `sword/phase_5_phish.py:58` | SMTP username |
| `FROM_ADDR` | `sword/phase_5_phish.py:60` | Sender email (different from `FROM_EMAIL`) |
| `SUBFINDER_PATH` | `brain/target_profiler.py:3` | Subfinder binary (different from `SUBFINDER_CONFIG`) |
| `NMAP_PATH` | `brain/target_profiler.py:4` | Nmap binary path |
| `WHATWEB_PATH` | `brain/target_profiler.py:5` | WhatWeb binary path |
| `DNS_RECON_PATH` | `brain/target_profiler.py:6` | DNSRecon binary path |
| `BRAIN_DB` | `adaptive_brain.py:4` | Brain database path |
| `BRAIN_PORT` | `brain/api.py:246` | Brain API server port |
| `C2_PSK` | `c2_channel.py:24` | C2 pre-shared key |
| `C2_TASK_DIR` | `c2_channel.py:26` | C2 tasks directory |
| `C2_URL` | `c2_channel.py:216` | C2 endpoint URL |
| `AGENT_ID` | `c2_channel.py:217` | C2 agent identifier |
| `AUDIT_DIR` | `audit_trail.py:15` | Audit log path |
| `ORCHESTRATOR_URL` | `sast/pipeline.py:7` | SAST orchestrator URL |
| `ADVERSARY_PROFILE` | `exploits/vulnu_harness.py:75` | Stealth profile |
| `TELEGRAM_TOKEN` | `telegram mcp/telegram_bot.py:18` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | `telegram mcp/telegram_bot.py:19` | Allowed chat ID |
| `WORK_DIR` | `telegram mcp/telegram_bot.py:20` | Working directory |
| `OPENCODE_CMD` | `telegram mcp/telegram_bot.py:21` | OpenCode binary path |
| `STRIX_IMAGE` | `runtime/docker_client.py:9` | Strix sandbox image |
| `PIPELINE_HOST` | `brain/autonomous.py:28,69` | Pipeline host |
| `SKILLS_REPO` | `skills_bridge.py:5` | Skills repo path |
| `CENSYS_API_KEY` | `sword/api.py:37` | Censys API key |
| `MHDDOS_API` | `raphael_cli.py:241` | MHDDoS service URL |
| `CLOAK_API` | `raphael_cli.py:254` | Cloak service URL |
| `C2_API` | `raphael_cli.py:267` | C2 service URL |
| `PHISH_API` | `raphael_cli.py:282` | Phishing service URL |
| `VULNU_PORT` | `exploit_*.py` (multiple) | Vulnerable lab port |
| `TEMPLATE_DIR` | `phishing/main.py:21` | Phishing template dir |
| `RAPHAEL_DATA_DIR` | `run_osmania_autonomous.py:12` | Data directory override |
| `TEAMS_OUTPUT` | `teams.py:267` | Teams output file |
| `PAPER_TEXT_PATH` | `rsi_paper_analysis.py:19` | Research paper text |
| `CACHED_REAL_IP` | `proxy_guard.py:839` | Cached external IP |
| `MIMICRY_*` (6 vars) | `proxy_guard.py` | Behavioral mimicry config |

---

## 3. Setup from Scratch (WSL Format Recovery)

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install -y curl wget git jq ca-certificates \
    tor netcat-openbsd dnsutils wireguard python3 python3-pip python3-venv nmap

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in, or: newgrp docker

# 3. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 4. Install Go 1.22+
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# 5. Clone the repo
git clone git@github.com:The-Despicable/raphael-2.0.git
cd raphael-2.0

# 6. Set up Python venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 7. Configure environment
cp .env.example .env
nano .env   # Add at minimum: NVIDIA_API_KEY or OPENAI_API_KEY

# 8. Pull Ollama models (proxy models — no local weights needed)
ollama pull blackgrg26/WORMGPT-13:latest
ollama pull minimax-m3:cloud
ollama pull bjoernb/gemma4-31b-think

# 9. Build Docker images
docker compose build --parallel

# 10. Verify
docker compose pull   # For tor-proxy, neo4j, caido images
docker compose up -d
docker compose ps

# 11. Verify all services are healthy
for port in 3201 3301 3401 3501 3502 3503 3600 3700 9050; do
    curl -s -o /dev/null -w "%{http_code}" http://localhost:$port/health 2>/dev/null || echo "$port: no response"
done
```

### Bootstrap Script

The repo includes `bootstrap.sh` which automates steps 1-9:

```bash
cd raphael-2.0
bash bootstrap.sh          # Installs everything, builds Docker images
nano .env                  # Add your API keys
docker compose up -d       # Start services
source .venv/bin/activate
python orchestrator/app.py # Use the CLI
```

---

## 4. OPSEC Setup (Mandatory Before Any Target Contact)

### 4.1 Tor

```bash
# Start Tor
sudo tor -f /etc/tor/torrc &
sleep 5

# Verify
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Expected: {"IsTor": true, "IP": "185.220.101.x"}
```

### 4.2 Kill Switch

```bash
# Block all non-Tor traffic
sudo bash setup_killswitch.sh
```

### 4.3 Full Anonymous Layer

```bash
bash setup_anon.sh
```

### 4.4 Pre-Flight Checklist (from `procedure.md`)

- [ ] Tor running on 9050
- [ ] Exit IP ≠ Real IP
- [ ] WireGuard up (`wg show wg0`)
- [ ] DNS not leaking (direct dig fails)
- [ ] IPv6 disabled
- [ ] New Tor circuit per target
- [ ] Randomized User-Agent per session
- [ ] Timing profile set per target
- [ ] Kill switch armed

---

## 5. Audit Findings (Issues Documented, Not Fixed)

The following issues were discovered during a deep end-to-end audit. All have been remediated in commit `163fa20`.

| # | Issue | File | Detail | Fix |
|---|-------|------|--------|-----|
| 1 | **brain/api.py missing** | `brain/Dockerfile` | False alarm — module exists at `orchestrator/brain/api.py`. Build context is project root, not `brain/`. | CMD updated to `orchestrator.brain.api:app` in `brain/Dockerfile` |
| 2 | **Hardcoded sudo password** | `raphael_anonymity_test.sh` | Sudo password `23532231` piped to `sudo -S` in 4 places. | All replaced with `sudo -n` |
| 3–5 | **HRM paths broken** | `start_hrm.sh`, `config/hrm_service.conf` | HRM subsystem decommissioned (hardware bottleneck). |
| 6 | **5 data files not found** | `orchestrator/run_osmania_autonomous.py` | Files expected in `data/` don't exist. | Added `docs/osmania-recon/` fallback path |
| 7 | **MCP hub network mismatch** | `mcp-hub/docker-compose.yml` | `name: raphael-2.0` doesn't match auto-generated `raphael-2.0_raphael-net`. | Changed to `name: raphael-2.0_raphael-net` |
| 8 | **Undefined `$VPN_IF`** | `kill_switch_status.sh:17` | Expands to empty string. | Changed to literal `tun1` |
| 9 | **Missing shebangs** | 6 `run_*.py` files | 3 files missing shebangs (`run_resume_rsi.py`, `run_debate_rsi.py`, `run_osmania_autonomous.py`). Other 3 already had them. | `#!/usr/bin/env python3` added to 3 files |
| 10 | **`.env.example` 56% stale** | `.env.example` | 27 stale vars removed. `FROM_EMAIL`→`FROM_ADDR`, `SUBFINDER_CONFIG`→`SUBFINDER_PATH`. | Cleaned in commit |
| 14 | **`WORKING_ALIASES` out of sync** | `providers.py` | Missing `glm`, `nemotron-super-120b`, `nemotron-super15`. | Added to list |
| 15 | **`JWT_SECRET` dead config** | `.env.example`, `raphael_cli.py` | No code signs or verifies JWTs. | Removed from both files |
| 16 | **Hardcoded container names** | `raphael_anonymity_test.sh:143` | Names depend on compose project name. | Changed to `docker compose ps -q <service>` dynamic lookup |

---

## 6. Quick Command Reference

```bash
# ── CLI Modes ──
python orchestrator/app.py                            # Show available modes
python orchestrator/app.py debate "question"          # Multi-model debate
python orchestrator/app.py community "question"       # Community analysis
python orchestrator/app.py rsi "research task"        # Recursive self-improvement
python orchestrator/app.py scan <target>              # Network scan
python orchestrator/app.py autonomous <target>        # Full autonomous engagement
python orchestrator/app.py deep_research "topic"      # Web research pipeline
python orchestrator/app.py postmortem "task"          # Failure analysis

# ── Team Workflows ──
python -m orchestrator.teams debate "question"        # Parallel model debate
python -m orchestrator.teams analyze "question"       # Reasoning chain
python -m orchestrator.teams code "prompt"            # Code generation chain
python -m orchestrator.teams execute "task"           # Offensive execution chain

# ── Pipeline Modes ──
python orchestrator/app.py exploit <target>           # Exploitation pipeline
python orchestrator/app.py postex <target_ip>         # Post-exploitation
python orchestrator/app.py exfil "<data>"             # Data exfiltration
python orchestrator/app.py phish                      # Phishing campaign
python orchestrator/app.py hexstrike <target>         # HexStrike MCP
python orchestrator/app.py osint <target>             # OSINT gathering
python orchestrator/app.py recon <target>             # Deep recon
python orchestrator/app.py mcp                        # MCP server

# ── Docker ──
docker compose up -d                                  # Start all services
docker compose down                                   # Stop all services
docker compose logs -f <service>                      # Follow service logs
docker compose build --parallel <service>             # Rebuild single service

# ── Anonymity ──
sudo bash setup_killswitch.sh                         # Block all non-Tor traffic
bash setup_anon.sh                                    # Deploy full anon layer
bash kill_switch_disable.sh                           # Remove kill switch
bash kill_switch_status.sh                            # Check kill switch state

# ── MCP Hub (standalone) ──
cd mcp-hub && docker compose up -d                    # Start MCP hub on :8000
```

---

## 7. File Size Reference

| File | Size | Notes |
|------|------|-------|
| Total repo | ~15MB | 439 files |
| `orchestrator/providers.py` | 359 lines | Core model routing |
| `orchestrator/app.py` | 529 lines | CLI entry point |
| `orchestrator/proxy_guard.py` | ~900 lines | Tor enforcement |
| `orchestrator/teams.py` | ~270 lines | Team workflows |
| `orchestrator/brain/adaptive_brain.py` | ~500 lines | Model selector |
| `docker-compose.yml` | 249 lines | 11 services |
| `ghost.md` | 934 lines | Invisibility reference |
| `procedure.md` | 496 lines | OPSEC protocol |
| `docs/raphael-2.0-blueprint.md` | 784 lines | Architecture blueprint |
