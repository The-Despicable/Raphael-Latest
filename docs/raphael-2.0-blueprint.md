# Raphael 2.0 — Autonomous AI Security Platform

> **Quick setup:** See `raphael-2.0/QUICKSTART.md` for a <30-minute rebuild guide.
> **Pre-flight protocol:** `raphael-2.0/procedure.md` — mandatory OPSEC checks before every operation.

Built from scratch, informed by Raphael 1.0's architecture and 1+ hour of multi-platform research judged by dual worm models (wormgpt12 + wormgpt13).

## Repo Status

| Item | Detail |
|------|--------|
| Git origin | `github.com:The-Despicable/raphael-autonomous.git` |
| Branch | `main` — single initial commit |
| All source | Inside `raphael-2.0/` directory |
| .env | NEVER committed (in `.gitignore`) |

---

## Lessons from Raphael 1.0

| Issue | Fix in 2.0 |
|-------|-------------|
| Docker Tor container unreliable | Native Tor on host, containers reach via `host.docker.internal:9050` |
| Provider routing spaghetti | Single `auto` router with per-model config, no hardcoded `NVIDIA_MODELS`/`GROQ_MODELS` sets |
| RSI limited to 1 judge model | Support N judges with configurable aggregation |
| Cloak-service Tor proxy fragile | Direct Tor SOCKS5, no intermediary proxy |
| CAI agents return generic advice | Each agent gets real tool execution (subfinder, nmap, sqlmap, etc.) |
| No centralized state/DB | SQLite with encryption, checkpoint/restore for long-running ops |
| Scope enforcement scattered | Single `SCOPE` regex validator at orchestrator entry point |

---

## Tool Repositories to Include

### Tier 1 — Core Infrastructure (MUST HAVE)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [HexStrike AI MCP](https://github.com/0x4m4/hexstrike-ai) | 9964 | AI-to-tool bridge for 150+ security tools | MCP server wrapping all Raphael agents |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 22000+ | Template-based vulnerability scanner | Auto-pipeline target discovery |
| [reconftw](https://github.com/six2dez/reconftw) | 7731 | Fully automated recon pipeline | First-stage of every engagement |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | 32000+ | SQL injection automation | Exploit agent's primary weapon |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | 78702 | Payload/ bypass encyclopedia | Vector DB for payload generation |

### Tier 2 — Post-Exploitation & C2 (HIGH PRIORITY)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [pupy](https://github.com/n1nj4sec/pupy) | 8985 | Cross-platform C2 + post-exploitation | Agent deploys pupy implants |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | 5403 | WinRM shell for Windows | Windows post-exploitation |
| [NetExec](https://github.com/Pennyw0rth/NetExec) | 5637 | Network execution & lateral movement | AD/network lateral movement |
| [Villain](https://github.com/t3l3machus/Villain) | 4401 | Stage 0/1 C2 framework | Lightweight C2 for quick shells |
| [Ladon](https://github.com/k8gege/Ladon) | 5299 | Large-scale intranet scanner | Internal network pivoting |

### Tier 3 — Recon & OSINT (MEDIUM PRIORITY)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | 6677 | Web fingerprint scanner | Tech stack identification |
| [spiderfoot](https://github.com/smicallef/spiderfoot) | 12000+ | OSINT automation | Passive intel gathering |
| [karma_v2](https://github.com/Dheerajmadhukar/karma_v2) | 998 | Passive OSINT recon framework | Automated passive recon |
| [mosint](https://github.com/alpkeskin/mosint) | 5902 | Email OSINT | Target email investigation |
| [secator](https://github.com/freelabz/secator) | 1297 | Pentester's swiss knife | Multi-tool orchestration |

### Tier 4 — Exploitation & Web Attacks (MEDIUM PRIORITY)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [OWASP Nettacker](https://github.com/OWASP/Nettacker) | 5265 | Automated pentesting framework | Scan-Exploit pipeline |
| [afrog](https://github.com/zan8in/afrog) | 4316 | Bug bounty/pentest scanner | Secondary vulnerability scanner |
| [autossrf](https://github.com/Th0h0/autossrf) | 364 | SSRF vulnerability scanner | SSRF exploitation |
| [yaklang/yakit](https://github.com/yaklang/yakit) | 7396 | All-in-one security platform | Alternative orchestrator UI |

### Tier 5 — Tunneling & Infrastructure (MEDIUM PRIORITY)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [Redcloud](https://github.com/khast3x/Redcloud) | 1278 | Automated red team Docker infra | Deploy proxy chains |
| [BounceBack](https://github.com/D00Movenok/BounceBack) | 1089 | Stealth redirector | C2 traffic obfuscation |
| [smtp-tunnel](https://github.com/x011/smtp-tunnel-proxy) | 1588 | Covert TCP over SMTP | Data exfiltration |
| [overlord](https://github.com/qsecure-labs/overlord) | 634 | Red team infra automation | Infra-as-code deployment |

### Tier 6 — Phishing & Social Engineering (MEDIUM PRIORITY)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [GoPhish](https://github.com/gophish/gophish) | 11000+ | Phishing campaign automation | Phishing agent |
| [EvilGinx](https://github.com/kgretzky/evilginx2) | 11000+ | Credential harvesting reverse proxy | MFA bypass + cred theft |
| [SET](https://github.com/trustedsec/social-engineer-toolkit) | 11000+ | Social engineering toolkit | Multi-vector social engineering |

### Tier 7 — MCP Servers (AI Integration Layer)

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [h1-brain MCP](https://github.com/PatrikFehrenbach/h1-brain) | 313 | HackerOne + AI agent bridge | Bug bounty auto-submission |
| [BurpMCP](https://github.com/swgee/BurpMCP) | 50 | Burp Suite MCP server | Burp integration |
| [mcpstrike](https://github.com/ente0/mcpstrike) | 9 | MCP autonomous pentesting | Reference implementation |
| [cybersec-mcp](https://github.com/26zl/cybersec-toolkit) | 18 | 580+ tools via MCP | Tool catalog |

### Tier 8 — Credential & Password Attacks

| Tool | Stars | Purpose | Integration |
|------|-------|---------|-------------|
| [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) | 6626 | Default credentials database | Credential stuffing |
| [hashcat](https://github.com/hashcat/hashcat) | 21000+ | GPU password cracking | Hash cracking |
| [JohnTheRipper](https://github.com/openwall/john) | 11000+ | Password cracking | Offline credential attacks |

---

## Retained from Raphael 1.0

### CAI Service (Cyber AI Agents)

8 agents kept and upgraded:

| Agent | Function | 2.0 Upgrade |
|-------|----------|-------------|
| **recon** | Subdomain enumeration, DNS recon | Real `subfinder`/`reconftw` execution, not simulated |
| **scan** | Port scanning, service discovery | `nmap` + `nuclei` integration |
| **exploit** | Vulnerability exploitation | `sqlmap` + metasploit + custom payloads |
| **defend** | Blue team / defensive recommendations | Network scan + CVE lookup integration |
| **forensic** | Post-incident analysis | Log parsing + IOC extraction |
| **oracle** | Oracle DB query agent | Direct SQL execution on target |
| **chat** | General security Q&A | RAG over tool output database |
| **audit** | Compliance and reporting | Auto-generate pentest reports |

### MHDDoS Service

Stress-testing capability retained:
- UDP/TCP/HTTP/Slowloris methods
- Tor proxy rotation for DDoS
- Multi-threaded attack engine
- Scoped to `SCOPE` targets only

### Cloak Service (Browser Automation)

Playwright-based browser agent:
- Headless Chrome through Tor
- `/browse` — fetch page content
- `/screenshot` — visual capture
- `/interact` — NEW: form fill + click + extract

---

## Architecture Blueprint

### Worm Model Judgment (The Sword)

Both worm models evaluated and scored all capabilities. **Consensus priorities:**

```
LETHALITY (L) + AUTOMATION (A) rating — scale 1-10 each
```

| Capability | L | A | Total | wormgpt12 | wormgpt13 | Priority |
|------------|---|---|-------|-----------|-----------|----------|
| MCP Tool Server (HexStrike) | 10 | 10 | **20** | 19 | 20 | 1 |
| Autonomous Recon Pipeline | 9 | 10 | **19** | 19 | 19 | 2 |
| Nuclei Scanning Engine | 10 | 10 | **20** | — | 20 | 3 |
| SQLi Automation (sqlmap) | 9 | 7 | **16** | 17 | 16 | 4 |
| C2 Deployment (pupy) | 9 | 9 | **18** | 18 | 18 | 5 |
| Phishing Ops (GoPhish) | 9 | 9 | **18** | 17 | 18 | 6 |
| Network Ops (nmap/NetExec) | 9 | 8 | **17** | 18 | 16 | 7 |
| Docker Infra (Redcloud) | 8 | 9 | **17** | 16 | 17 | 8 |
| Web Exploit (Nettacker) | 8 | 8 | **16** | 16 | 16 | 9 |
| WinRM Post-Exploit | 8 | 8 | **16** | — | 16 | 10 |
| Covert Tunnel (smtp-tunnel) | 7 | 8 | **15** | — | — | 11 |
| MFA Bypass (EvilGinx) | 10 | 7 | **17** | — | 17 | 12 |

### Containers & Ports

```
raphael-2.0/
├── docker-compose.yml
├── .env                          # All API keys
│
├── orchestrator/                 # :3100 — AI orchestration hub
│   ├── app.py                    # FastAPI + routing + auth
│   ├── modes/
│   │   ├── single.py             # Direct model call
│   │   ├── ensemble.py           # N models vote
│   │   ├── pipeline.py           # Chain: recon → scan → exploit
│   │   ├── rsi.py                # Recursive self-improvement
│   │   ├── sword_review.py       # Multi-model SWORD analysis
│   │   ├── anon_rsi.py           # RSI through Tor
│   │   ├── swarm.py              # NEW: multi-agent swarm
│   │   └── providers.py          # Model routing (single `auto` router)
│   └── mcp-server/               # NEW: MCP tool server
│       ├── server.py             # MCP protocol bridge
│       └── tools/                # Tool wrappers for 150+ tools
│           ├── recon/            # reconftw, subfinder, amass
│           ├── exploit/          # sqlmap, nuclei, metasploit
│           ├── c2/               # pupy, evil-winrm
│           └── phish/            # GoPhish, EvilGinx
│
├── cai-service/                  # :3200 — AI security agents
│   ├── agents/
│   │   ├── recon.py              # subfinder + reconftw + amass
│   │   ├── scan.py               # nmap + nuclei + nikto
│   │   ├── exploit.py            # sqlmap + metasploit + custom
│   │   ├── defend.py
│   │   ├── forensic.py
│   │   ├── oracle.py
│   │   ├── chat.py
│   │   └── audit.py
│   └── Dockerfile
│
├── mhddos-service/               # :3300 — DDoS stress-testing
│   ├── app.py
│   ├── methods/                  # UDP, TCP, HTTP, Slowloris
│   └── Dockerfile
│
├── cloak-service/                # :3400 — Browser automation
│   ├── app.py                    # Playwright through Tor
│   ├── interact.py               # NEW: form fill + click
│   └── Dockerfile
│
├── mcp-hub/                      # NEW: :3500 — MCP server hub
│   ├── server.py                 # HexStrike-style MCP
│   └── tool-registry.json        # All available tool wrappers
│
├── c2-server/                    # NEW: :3501 — C2 control
│   ├── pupy-server/              # pupy listener
│   └── villian-server/           # Villain listener
│
├── phishing/                     # NEW: :3502 — Phishing infra
│   ├── gophish/                  # GoPhish API + dashboard
│   └── evilginx/                 # EvilGinx reverse proxy
│
├── recon-pipeline/               # NEW: standalone recon engine
│   ├── pipeline.py               # reconftw → nuclei → whatweb
│   └── Dockerfile
│
├── db/
│   ├── sqlite/                   # Encrypted run database
│   └── vector-store/             # Payload/technique vector DB
│
└── shared/
    ├── scope.py                  # Target scope validation
    ├── tor.py                    # Tor SOCKS5 + circuit rotation
    └── encrypt.py                # Fernet encryption
```

### Orchestrator Blueprint

```python
# orchestrator/app.py — Raphael 2.0 Core

@router.post("/v1/chat/completions")
async def chat_completion(req):
    # 1. Scope enforcement (all targets validated)
    ScopeValidator.enforce(req)

    # 2. Route by model
    match req.model:
        case "single":     routing.single(req)
        case "ensemble":   routing.ensemble(req)    # N models vote
        case "pipeline":   routing.pipeline(req)    # recon→scan→exploit
        case "rsi":        routing.rsi(req)          # self-improvement loop
        case "swarm":      routing.swarm(req)        # multi-agent swarm
        case "sword":      routing.sword_review(req) # offensive analysis
        case "recon"|"scan"|"exploit"|"defend"|
             "forensic"|"oracle"|"chat"|"audit":
                           routing.cai_agent(req)    # CAI service
        case _:            routing.single(req)

    # 3. Log + checkpoint
    state.checkpoint(req.model, req.messages, result)
```

### Routing Architecture

```
                    ┌─────────────────────────────┐
                    │    Orchestrator :3100        │
                    │   (FastAPI + MCP Server)     │
                    └──────────┬──────────────────┘
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  FreeLLM   │ │   Groq    │ │  NVIDIA    │
        │  :3001     │ │  API      │ │  API       │
        └────────────┘ └────────────┘ └────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
   ┌─────────┐  ┌─────────┐
   │ Ollama  │  │ Ollama  │
   │ Local   │  │ Cloud   │
   └─────────┘  └─────────┘

                    ┌─────────────────────────────┐
                    │      MCP Hub :3500           │
                    │  (HexStrike-style tool MCP)  │
                    └──────────┬──────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Tool Layer  │     │  CAI Agents  │     │  External    │
│  (150+tools) │     │  (8 agents)  │     │  APIs        │
│  · nmap      │     │  · recon     │     │  · Shodan    │
│  · sqlmap    │     │  · scan      │     │  · Censys    │
│  · nuclei    │     │  · exploit   │     │  · crt.sh    │
│  · metasploit│     │  · defend    │     │  · VT        │
│  · subfinder │     │  · forensic  │     │  · H1        │
│  · etc       │     │  · oracle    │     └──────────────┘
│               │     │  · chat     │
│               │     │  · audit    │
└──────────────┘     └──────────────┘
```

### The Sword — Offensive Pipeline

Worm model-judged optimal attack flow:

```
Phase 0: Recon
  └─ reconftw → spiderfoot → crt.sh → Shodan
  └─ Output: subdomains, IPs, tech stack, emails

Phase 1: Scanning
  └─ nuclei (templates) → nmap (ports) → whatweb (fingerprint)
  └─ Output: CVE list, open ports, WAF detection

Phase 2: Exploitation
  └─ sqlmap (SQLi) → autossrf (SSRF) → Nettacker (multi-vector)
  └─ Payload: PayloadsAllTheThings vector DB
  └─ Output: shells, creds, data

Phase 3: Post-Exploitation
  └─ pupy (C2 implant) → evil-winrm (Windows) → NetExec (lateral)
  └─ Ladon (intranet scan) → Ladon (intranet scan)
  └─ Output: persistent access, domain dominance

Phase 4: Exfiltration
  └─ smtp-tunnel (covert data out) → BounceBack (stealth redirector)
  └─ Output: exfiltrated data

Phase 5: Phishing (alternate vector)
  └─ GoPhish (campaign) → EvilGinx (cred harvest) → SET (multi-vector)
  └─ Output: credentials, session tokens, MFA bypass
```

### CAI Agent Pipeline

```
User Request
    │
    ▼
Orchestrator validates scope
    │
    ├──┐
    │  │
    ▼  ▼
recon  scan    exploit    defend   forensic   oracle   chat   audit
│     │       │         │        │          │        │      │
│     │       │         │        │          │        │      │
▼     ▼       ▼         ▼        ▼          ▼        ▼      ▼
reconftw  nmap    sqlmap    CVE     IOC       SQL    RAG     Report
subfinder nuclei  metasploit lookup  extract   query  over    generator
amass     nikto   custom     │        │        │     tool    │
whatweb   │       payloads   │        │        │     output  │
spiderfoot│        │         │        │        │      │      │
          │        │         │        │        │      │      │
          └────────┴─────────┴────────┴────────┴──────┴──────┘
                              │
                              ▼
                    Encrypted SQLite DB
                    (checkpointed state)
```

### MHDDoS Integration

```
Stress Test Request
    │
    ▼
Orchestrator validates target in SCOPE
    │
    ▼
MHDDoS Service :3300
    │
    ├── Method selection: UDP/TCP/HTTP/Slowloris
    ├── Tor proxy rotation (newnym per attack)
    ├── Thread pool management
    └── Result: attack duration, packets sent, success rate
```

### Model Routing (Simplified in 2.0)

```python
# Single auto-router — no hardcoded sets

ALIASES = {
    "wormgpt12": "blackgrg26/WORMGPT-12:latest",
    "wormgpt13": "blackgrg26/WORMGPT-13:latest",
    "deepseek":  "deepseek-ai/deepseek-v4-flash",
    "nemotron":  "nvidia/nemotron-3-super-120b-a12b",
    "kimi":      "moonshotai/kimi-k2.6",
    "qwen":      "qwen/qwen3.6-27b",
    "llama":     "llama-3.3-70b-versatile",
    "auto":      "auto",  # freellmapi decides
}

# Provider chain: try each in order until one works
PROVIDER_CHAIN = ["freellmapi", "groq", "nvidia", "ollama_cloud", "ollama_local"]
```

### Key Differences from 1.0

| Aspect | Raphael 1.0 | Raphael 2.0 |
|--------|-------------|-------------|
| Provider routing | Hardcoded model→provider maps | Dynamic chain with `auto` fallback |
| Tool execution | Simulated (CAI generated text) | Real tool execution via MCP |
| C2 | None | pupy + Villain + evil-winrm |
| Phishing | None | GoPhish + EvilGinx + SET |
| MCP integration | None | HexStrike-style MCP server |
| Swarm agents | None | Multi-agent swarm execution |
| Payload DB | None | PayloadsAllTheThings vector DB |
| State checkpoint | Basic SQLite | SQLite + checkpoint/restore |
| Tunneling | None | Redcloud + BounceBack + smtp-tunnel |
| AD attacks | None | NetExec + BloodHound + Impacket |
| Cloud pentesting | None | CloudGoat + ScoutSuite |
| Oracle DB | Direct query | Wrapped in oracle agent |

### Build Order

```
Week 1: Core Infrastructure
  └─ Docker compose with all containers
  └─ Single auto-router (providers.py)
  └─ MCP hub server
  └─ Tor integration (native, not Docker)

Week 2: Recon & Scanning
  └─ reconftw → nuclei → whatweb pipeline
  └─ CAI recon agent with real subfinder
  └─ CAI scan agent with real nmap
  └─ crt.sh + Shodan + Censys API integration

Week 3: Exploitation
  └─ sqlmap wrapper in exploit agent
  └─ PayloadsAllTheThings vector DB
  └─ Nuclei template executor
  └─ autossrf + Nettacker integration

Week 4: C2 & Post-Exploitation
  └─ pupy server deployment
  └─ evil-winrm integration
  └─ NetExec lateral movement
  └─ Ladon intranet scanner

Week 5: Phishing & Social
  └─ GoPhish campaign automation
  └─ EvilGinx proxy deployment
  └─ SET integration

Week 6: Infrastructure & Tunneling
  └─ Redcloud Docker infra auto-deploy
  └─ BounceBack redirector
  └─ smtp-tunnel exfiltration

Week 7: MCP & Swarm
  └─ HexStrike-style MCP server
  └─ Swarm mode (multi-agent orchestration)
  └─ h1-brain + BurpMCP integration

Week 8: Hardening & Testing
  └─ Scope enforcement hardening
  └─ Tor rotation on every request
  └─ Rate limiting + WAF avoidance
  └─ Full end-to-end test against scope targets

---

## Appendix: Performance Optimizations

*Researched by wormgpt12, judged 9/10 by wormgpt13. Adapted to Raphael 2.0 with real provider benchmarks.*

### 1. Per-Model Timeout Configuration

Observed latency per provider during Phase 0 testing:

| Provider | Connect | First Token | Full Response | Failure Mode |
|----------|---------|-------------|---------------|--------------|
| **Ollama Local** (wormgpt12/13) | <1s | <2s | 2-10s | Model not loaded |
| **Groq** (llama, qwen) | 1-3s | 2-5s | 5-30s | Rate limit (429) |
| **NVIDIA** (nemotron) | 2-5s | 3-8s | 10-60s | Rate limit (429) or 403 |
| **Ollama Cloud** (devstral-2) | 2-5s | 5-15s | 15-60s | Model not found (404) |
| **FreeLLMAPI** (auto) | 1-3s | 3-10s | 10-120s | All backends exhausted |

```python
# Timeout config per provider — used by providers.py
PER_PROVIDER_TIMEOUT = {
    "ollama_local": {
        "connect": 5,
        "read": 30,
        "total": 60,
        "retries": 1,
        "backoff": 1.0,       # fast retry for local
    },
    "groq": {
        "connect": 10,
        "read": 60,
        "total": 120,
        "retries": 2,
        "backoff": 2.0,
        "on_429": "skip_chain",  # 429 means rate limited, skip this provider
    },
    "nvidia": {
        "connect": 10,
        "read": 120,
        "total": 180,
        "retries": 3,
        "backoff": 4.0,       # NVIDIA needs longer backoff
        "on_429": "wait",     # wait and retry (rate limit resets)
    },
    "ollama_cloud": {
        "connect": 10,
        "read": 60,
        "total": 120,
        "retries": 2,
        "backoff": 2.0,
    },
    "freellmapi": {
        "connect": 10,
        "read": 180,
        "total": 300,          # catch-all, longest timeout
        "retries": 4,
        "backoff": 2.0,
    },
}

# Per-model timeout overrides (alias-level)
MODEL_TIMEOUT_OVERRIDES = {
    "wormgpt12": {"provider": "ollama_local", "total": 30},
    "wormgpt13": {"provider": "ollama_local", "total": 30},
    "deepseek":  {"provider": "nvidia", "total": 180},
    "nemotron":  {"provider": "nvidia", "total": 180},
    "qwen":      {"provider": "groq", "total": 60},
    "llama":     {"provider": "groq", "total": 60},
}
```

**Expected improvement**: 40-60% fewer timeout errors. Local models no longer wait 300s. NVIDIA gets proper backoff. Groq 429s skip immediately instead of retrying 4 times.

### 2. Token Usage Reduction Strategies

Observed token consumption per mode (from 1.0 runs):

| Mode | Avg Tokens/Request | Avg Tokens/Iteration | Waste % |
|------|-------------------|---------------------|---------|
| single | 1,200 | — | 20% |
| rsi (per iter) | 8,500 | 12,000 | 60% |
| ensemble (4 models) | 6,400 | — | 40% |
| pipeline (3 steps) | 5,100 | — | 35% |
| CAI agent | 3,200 | — | 25% |

```python
# Token budget configuration
TOKEN_BUDGETS = {
    "single":    {"max_input": 2048,  "max_output": 1024, "max_history": 2},
    "ensemble":  {"max_input": 4096,  "max_output": 1024, "max_history": 1},
    "pipeline":  {"max_input": 2048,  "max_output": 2048, "max_history": 0},
    "rsi":       {"max_input": 4096,  "max_output": 2048, "max_history": 1,
                  "summarize_between": True},
    "cai_agent": {"max_input": 4096,  "max_output": 1024, "max_history": 1},
}

class TokenBudget:
    def __init__(self, mode: str):
        cfg = TOKEN_BUDGETS.get(mode, TOKEN_BUDGETS["single"])
        self.max_input = cfg["max_input"]
        self.max_output = cfg["max_output"]
        self.max_history = cfg["max_history"]

    def truncate_messages(self, messages: list) -> list:
        # Keep system prompt + last N exchanges
        system = [m for m in messages if m["role"] == "system"]
        history = [m for m in messages if m["role"] != "system"]
        if len(history) > self.max_history * 2:
            # Summarize old history
            old = history[:-(self.max_history * 2)]
            recent = history[-(self.max_history * 2):]
            summary = f"[Previous context: {len(old)} messages summarized]"
            history = [{"role": "system", "content": summary}] + recent
        return system + history

    def compute_max_tokens(self, input_length: int) -> int:
        # Reserve tokens for output based on input usage
        remaining = self.max_input - input_length
        return min(self.max_output, max(remaining // 2, 64))
```

**Expected improvement**: 50-70% token reduction for RSI mode (summarization between iterations). 30-40% for pipeline/ensemble modes (history truncation). Free tier lasts 2-3x longer before hitting rate limits.

### 3. Other Optimizations

| Optimization | Technique | Expected Gain | Implementation |
|-------------|-----------|---------------|----------------|
| **Connection pooling** | Reuse httpx.AsyncClient per provider | 20-30ms saved per request | Add `client_pool = {}` dict in providers.py |
| **Parallel model calls** | asyncio.gather for ensemble/debate | 3-4x faster ensemble mode | Modify ensemble/debate handlers |
| **Response streaming** | Stream partial results to orchestrator | 2-3x perceived speed | SSE endpoint per mode |
| **Provider health checks** | Pre-check provider before chain | Skip dead providers in 1s | Background health-check coroutine |
| **Adaptive temperature** | 0.1 for recon, 0.7 for exploit, 0.9 for payload gen | Better output quality per task | Add `temperature_by_task` dict |
| **Result caching** | Cache identical tool outputs for 60s TTL | 80% cache hit on repeated scans | `lru_cache` with TTL decorator |
| **Lazy provider init** | Don't connect to providers until first use | 0 overhead for unused providers | Remove startup connectivity check |
| **Stop sequences** | Custom stop tokens per model | 10-20% token savings | Add `stop=["Observation:", "---"]` per task |

```python
# Connection pool
_client_pool = {}

def get_client(provider: str) -> httpx.AsyncClient:
    if provider not in _client_pool:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        _client_pool[provider] = httpx.AsyncClient(limits=limits, timeout=60)
    return _client_pool[provider]

# Result cache with TTL
from functools import lru_cache
import time

_result_cache = {}

async def cached_call(cache_key: str, ttl: int, call_fn):
    now = time.time()
    if cache_key in _result_cache:
        result, expiry = _result_cache[cache_key]
        if now < expiry:
            return result
    result = await call_fn()
    _result_cache[cache_key] = (result, now + ttl)
    return result

# Adaptive temperature
TASK_TEMPERATURE = {
    "recon":       0.1,    # deterministic — accurate output
    "scan":        0.1,
    "exploit":     0.5,    # balanced — needs precision + creativity
    "payload_gen": 0.9,    # creative — variety matters
    "rsi_generate": 0.85,  # creative generation
    "rsi_judge":   0.3,    # strict judgment
    "c2_command":  0.1,    # precise commands
    "phishing":    0.7,    # social engineering needs creativity
}

# Stop sequences
TASK_STOP = {
    "recon":        ["\n##", "\n---", "```\n\n"],
    "exploit":      ["\n##", "```\n\n"],
    "payload_gen":  ["\n##", "```\n\n"],
    "rsi_judge":    ["<<<", "```"],
}
```

### 4. Provider Chain Optimization (Current vs Optimized)

**Current** (from 1.0):
```
nvidia → ollama_cloud → ollama_cloud_2 → ollama_cloud_3 → groq → freellmapi
                                                            ↳ 3 retries each
                                                            ↳ 300s timeout each
```

**Optimized** (for 2.0):
```
freellmapi (10s) → groq (10s) → nvidia (10s) → ollama_cloud (10s) → ollama_local (5s)
    ↳ per-provider timeout from config
    ↳ provider health check before chain (skip dead immediately)
    ↳ on 429: fast-skip instead of retry
    ↳ parallel health-check during first request
```

**Total worst-case chain time**: 300s → **45s** (previously: 5 providers × 3 retries × 20s = 300s; now: 5 providers × 1 try × 10s connect + bypass dead = 45s)

### 5. Optimization Priorities (Build Order)

| Priority | Optimization | Effort | Impact | When |
|----------|-------------|--------|--------|------|
| 1 | Per-model timeout config | 30 min | High | Phase 0 |
| 2 | Token budgets + truncation | 1 hr | High | Phase 0 |
| 3 | Connection pooling | 15 min | Medium | Phase 1 |
| 4 | Adaptive temperature | 15 min | Medium | Phase 1 |
| 5 | Result caching | 30 min | Medium | Phase 1 |
| 6 | Parallel model calls | 1 hr | High | Phase 2 |
| 7 | RSI summarization | 2 hr | High | Phase 2 |
| 8 | Stop sequences | 15 min | Low | Phase 2 |
| 9 | Provider health checks | 1 hr | Medium | Phase 3 |
| 10 | Response streaming | 2 hr | Low | Phase 3 |

---

## Appendix: Anonymous OpSec Layer v2.0

*Designed by wormgpt12, judged 10/10 by wormgpt13.*

### Design Philosophy
> Zero Trust. Zero Persistence. Zero Trace.
Every component is ephemeral, containerized, and self-destructs without external instruction if compromised.

### Directory Structure
```
anonymous_layer/
├── config/
│   ├── scope.json              # Targets, rate limits, budgets
│   ├── tls_profiles/           # Rotating TLS fingerprints
│   ├── certs/                  # Ephemeral CA + cert chain
│   └── .secrets/               # Ephemeral keys (ramfs-only)
├── src/
│   ├── core/
│   │   ├── session.py          # Per-target session controller
│   │   ├── killswitch.py       # All kill signals → central handler
│   │   └── utils.py            # Randomizers, padding, timing
│   ├── hops/
│   │   ├── tor.py              # Stem-based Tor circuit mgmt
│   │   ├── cloudflare.py       # Dynamic Worker tunnel
│   │   └── ssh_tunnel.py       # Dynamic SSH SOCKS5
│   ├── validators/
│   │   ├── scope.py            # Pre-flight target validation
│   │   ├── fingerprint.py      # TLS/HTTP header randomizer
│   │   └── waf_detector.py     # Anomaly detection
│   ├── logging/
│   │   └── encrypted_logger.py # Ring buffer + oneshot encryption
│   └── orchestrator/
│       ├── orchestrator.py     # Heartbeat + state manager
│       └── api.py              # Remote kill endpoint (mTLS)
├── docker/
│   ├── Dockerfile              # DebianSlim + Python3.11, no shell
│   ├── docker-compose.yml
│   └── entrypoint.sh
└── tests/
    └── test_anon_layer.py
```

### Multi-Hop Proxy Chain
```
Target ← SSH Tunnel (ephemeral VM) ← Cloudflare Worker ← Tor (circuit-per-target) ← Raphael Orchestrator
    3rd hop                    2nd hop              1st hop                      source
```

### Kill Switch Hierarchy
| Signal | Trigger | Action | Propagation |
|--------|---------|--------|-------------|
| **Dead Man** | Heartbeat timeout (10s) | Kill all sessions, wipe state | Direct to orchestrator |
| **Circuit Break** | 3+ consecutive failures | Stop all outbound, alert | Via API |
| **Remote Kill** | Authenticated POST | Full teardown | mTLS endpoint |
| **Physical Kill** | TCP magic packet on :9999 | Immediate halt | Raw socket listener |
| **Scope Violation** | Regex mismatch on outbound | Kill that session only | Per-session monitor |

### Cleanup Sequence (Reverse Order)
```
1. SSH tunnel → disconnect, rotate keys
2. Cloudflare Worker → delete deployment, revoke API token
3. Tor → NEWNYM circuit rotation, discard identity
4. Local → shred RAMFS secrets, wipe encrypted log buffer, rotate encryption keys
5. Containers → docker rm (containers use --rm flag)
6. Orchestrator → kill heartbeat, zero memory, exit
```

### Forensics Denial Measures
- All logs encrypted with ephemeral key — key destroyed on cleanup
- Memory-only state (no disk writes)
- No persistent shell history, no temp files, no core dumps
- All timestamps randomized within ±5min window
- All payloads padded to random lengths (avg 512B ±256B)
- Connection timing randomized (100-500ms jitter)
- Separate Tor circuit per TARGET (never reuse)
- No identifying data in any request (no tool-revealing User-Agent)
- Containers auto-delete on stop (`--rm`)

### Worm Model Judgment Summary
| Criteria | Score | Notes |
|----------|-------|-------|
| **Completeness** | 10/10 | Covers all requirements with detailed implementation |
| **Stealth** | 9/10 | DNS/WebRTC leak prevention, timezone randomization |
| **Redundancy** | 9/10 | Multiple kill switches, no single point of failure |
| **Safety** | 10/10 | Scope validation, rate limiting, anomaly detection |
| **Cleanup Speed** | 9/10 | Reverse-chain teardown, container auto-removal |

**Overall: 9.5/10** — Only minor improvements needed (advanced fingerprinting, more proxy redundancy).
```
