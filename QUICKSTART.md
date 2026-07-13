# Raphael 2.0 — Quickstart

Rebuild from scratch in <30 minutes.

## 1. System Requirements

| Item | Required |
|------|----------|
| OS | Linux (Debian/Ubuntu) |
| Docker | 24+ with compose plugin |
| Tor | `apt install tor` |
| Ollama | `curl -fsSL https://ollama.com/install.sh \| sh` |
| Python | 3.11+ |
| Go | 1.21+ (for subfinder, nuclei) |
| RAM | 8GB+ (16GB recommended) |
| Disk | 20GB free |

## 2. Clone

```bash
git clone git@github.com:The-Despicable/raphael-2.0.git raphael-2.0
cd raphael-2.0
```

## 3. Environment

```bash
cp .env.example .env
# EDIT .env — set at minimum:
#   OPENAI_API_KEY=<your-openai-compatible-key>
#   OPENAI_API_KEY=<your-openrouter-or-other-key>
```

**Required keys (at least one):**

| Key | Provider | Get it |
|-----|----------|--------|
| `OPENAI_API_KEY` | OpenAI-compatible (Ollama) | provider dashboard → API |
| `OPENAI_API_KEY` | OpenAI/OpenRouter | platform.openai.com |
| `OMNIROUTE_API_KEY` | OmniRoute (free fallback) | localhost:20128 |

**Model inventory** (`orchestrator/providers.py`):
- **Code gen** (NVIDIA API): deepseek, nemotron, mistral-small
- **Reasoning** (NVIDIA API): nemotron-super, mistral-large, kimi
- **Offensive** (Ollama → ollama.com): wormgpt12/13, w480b
- **Fast reasoning** (Ollama): minimax-m3, gemma4

## 4. Tor & Proxy Chain

Follow `procedure.md` strictly. Quick start:

```bash
# Start Tor
sudo tor -f /etc/tor/torrc &
sleep 5

# Verify
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Apply kill switch (blocks all non-Tor traffic)
sudo bash setup_killswitch.sh

# Full anon layer
bash setup_anon.sh
```

**Stack:** `dnscrypt → Tor (9050) → WireGuard → FlareTunnel → Target`

## 5. Ollama (for Worm Models)

```bash
# Ollama proxies worm models to ollama.com — no local weights needed
ollama pull blackgrg26/WORMGPT-13:latest
ollama pull minimax-m3:cloud
ollama pull bjoernb/gemma4-31b-think
```

Verify:
```bash
curl http://localhost:11434/api/generate -d '{"model":"blackgrg26/WORMGPT-13:latest","prompt":"hello","stream":false}'
```

## 6. Docker

```bash
# Build & start all services
docker compose build --parallel
docker compose up -d

# Verify
docker compose ps
```

**Services (9 containers):**

| Service | Port | Role |
|---------|------|------|
| cai-service | 3201 | AI agent API |
| mhddos-service | 3301 | DDoS stress-test |
| cloak-service | 3401 | Playwright browser automation |
| c2-server | 3501 | C2 operations |
| phishing | 3502 | GoPhish campaigns |
| recon-pipeline | 3503 | Subfinder + nmap + nuclei |
| sword | 3600 | Full engagement pipeline |
| autonomous-brain | 3700 | Brain API (model selection, memory) |
| tor-proxy | 9050/9052 | Shared Tor exit |

**MCP Hub** (standalone):
```bash
cd mcp-hub && docker compose up -d
```

## 7. Usage

```bash
# CLI orchestrator
python orchestrator/app.py

# Common modes:
python orchestrator/app.py debate "How to enumerate subdomains?"
python orchestrator/app.py scan <target>
python orchestrator/app.py autonomous <target>
python orchestrator/app.py rsi "Research WAF evasion"
python orchestrator/app.py deep_research "Topic"
python orchestrator/app.py postmortem "Mission log"

# Team workflows:
python -m orchestrator.teams debate "Question"
python -m orchestrator.teams execute "Task for worm models"
python -m orchestrator.teams code "Write exploit script"
```

## 8. Key Files

| File | Purpose |
|------|---------|
| `orchestrator/providers.py` | 22 model aliases, auto-routing |
| `orchestrator/app.py` | CLI entry point, all modes |
| `orchestrator/proxy_guard.py` | Tor/proxy enforcement |
| `orchestrator/brain/adaptive_brain.py` | Thompson sampling model selector |
| `orchestrator/brain/neural_memory.py` | Episodic + semantic memory |
| `orchestrator/teams.py` | Team workflows (debate, analyze, code, execute) |
| `orchestrator/utils/undercover.py` | Text normalization (strip AI markers) |
| `orchestrator/utils/retry.py` | Exponential backoff + fallback chain |
| `orchestrator/critic.py` | Post-execution failure detector |
| `orchestrator/code_verifier.py` | Rejects code referencing non-existent endpoints |
| `orchestrator/modes/` | All execution modes |
| `orchestrator/agents/` | CAI agent implementations |
| `orchestrator/scanners/` | nmap, nuclei, spiderfoot wrappers |
| `orchestrator/exploit/` | sqlmap, payload generation |
| `orchestrator/postex/` | Post-exploitation pipelines |
| `orchestrator/exfil/` | Data exfiltration |
| `orchestrator/phishing/` | GoPhish + EvilGinx integration |
| `orchestrator/sast/` | SAST pipeline |
| `orchestrator/hexstrike_wrapper.py` | HexStrike MCP bridge |
| `orchestrator/spiderfoot_wrapper.py` | SpiderFoot OSINT |
| `orchestrator/karma_wrapper.py` | karma_v2 passive recon |
| `orchestrator/rag_knowledge.py` | RAG context for endpoints |
| `orchestrator/runtime/` | Session management |
| `sword/` | 6-phase engagement pipeline |
| `mcp-hub/` | MCP tool server (12+ tools) |
| `cai-service/` | CAI agent container |
| `c2-server/` | C2 operations container |
| `phishing/` | Phishing container |
| `recon-pipeline/` | Recon pipeline container |

## 9. HRM Setup (Optional)

```bash
# Requires: NVIDIA GPU with FlashAttention support
git clone https://github.com/sapientinc/HRM ../HRM
cd ../HRM
python3 -m venv .venv
source .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cu118
pip install fastapi uvicorn pydantic pyyaml tqdm huggingface-hub

# Start microservice
cd ../raphael-2.0
bash start_hrm.sh
```

## 10. Checklists

### Pre-flight (from `procedure.md`)
- [ ] Tor running on 9050 (`curl --socks5-hostname 127.0.0.1:9050 -s https://ifconfig.me`)
- [ ] Exit IP != Real IP
- [ ] WireGuard up (`wg show wg0`)
- [ ] DNS not leaking (direct dig should fail)
- [ ] IPv6 disabled
- [ ] New Tor circuit per target
- [ ] Randomized User-Agent
- [ ] Timing profile set
- [ ] Kill switch armed

### Docker Health
- [ ] `docker compose ps` — all 9 services running
- [ ] Ports 3201,3301,3401,3501,3502,3503,3600,3700,9050 accessible
- [ ] MCP hub running on localhost:9500 (if used)
- [ ] `.env` has at least OPENAI_API_KEY (for Ollama-connected models)

## 11. References

| Document | Location |
|----------|----------|
| Blueprint / Architecture | `../raphael-2.0-blueprint.md` |
| Pre-flight Protocol | `procedure.md` |
| Invisibility Layer | `ghost.md` |
| Failure Modes | `FAILURE_MODES.md` |
| HRM Integration | `HRM.md` |
| Complete Analysis | `raphael_complete_report.md` |
| Skills Integration | `skills_integration_report.md` |
| OSMANIA 2.0 Plan | `OSMANIA_2_0.md` |
| Fix Plan Verdict | `fixplan_debate_verdict.md` |
| Reasoning Team Plan | `reasoning_team_final_plan.md` |
| Hermes Recovery Map | `hermes-self-healing-recovery-map.md` |
| RSI Final Plan | `debate_rsi_final_plan.md` |
| RSI Team Report | `orchestrator/rsi_team_report_final.md` |
| RSI Paper Report | `orchestrator/rsi_paper_report_final.md` |
| Community Impl | `orchestrator/community_impl_final.md` |
| VulnU-Lab | `vulnu-lab/README.md` |
| Master Report | `../MASTER_REPORT.md` |
