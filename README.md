# Raphael 2.0 — Autonomous AI Security Platform

Autonomous penetration testing and red-team orchestration platform with multi-agent AI coordination, C2 infrastructure, and egress obfuscation.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    sword (orchestrator)              │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ cai-svc  │  │ mhddos   │  │ autonomous-brain  │  │
│  │ (LLM AI) │  │ (DDoS)   │  │ (agent manager)   │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ cloak    │  │ c2-svr   │  │ recon-pipeline    │  │
│  │ (proxy)  │  │ (C2)     │  │ (recon)           │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ phishing │  │ kali-tls │  │ raphael-api       │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────┘
         │                    │
    ┌────┴────┐         ┌────┴────┐
    │  Tor    │         │ Sliver  │
    │  proxy  │         │  C2     │
    └─────────┘         └─────────┘
```

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — set at minimum: NVIDIA_API_KEY, TOR_CONTROL_PASS, NEO4J_PASS, API_KEY

# 2. Verify configuration
python3 scripts/validate_env.py

# 3. Build and start
docker compose build
docker compose up -d

# 4. Check health
docker compose ps
curl http://localhost:3900/health
```

## Configuration

| Variable | Required | Description |
|---|---|---|
| `NVIDIA_API_KEY` | Yes | NVIDIA API key for LLM inference |
| `OPENAI_API_KEY` | No | Fallback OpenAI-compatible key |
| `TOR_CONTROL_PASS` | Yes | Tor control password (min 16 chars) |
| `API_KEY` | Yes | Internal API gateway key (min 32 chars) |
| `GOPHISH_API_KEY` | If phishing | Gophish API key (min 32 chars) |
| `NEO4J_PASS` | Yes | Neo4j database password (min 16 chars) |
| `SHODAN_API_KEY` | If recon | Shodan API key for reconnaissance |

## Operational Security

- **Do not run on your personal/work machine.** Raphael modifies network config, installs kernel modules, and generates traffic patterns that trigger alarms.
- **Default credentials are placeholders.** The validation script (`scripts/validate_env.py`) rejects weak/default values.
- **CDN fronting and TLS SNI spoofing use placeholder domains** by default. You must configure your own fronting infrastructure before use. Using real third-party domains (Amazon, Cloudflare, Google) for fronting is detectable and may be illegal in your jurisdiction.
- **Agent communications** are encrypted but certificate verification is disabled by default. Set `EGRESS_VERIFY_CERT=true` if your threat model requires MITM protection.
- **Logs** capture all C2 traffic at DEBUG level. Commands matching `REDACT_PATTERNS` (regex) are redacted from logs automatically.

## Legal & Ethical Use

This software is intended for **authorized security testing only**. You must:
1. Have written permission from the target system owner
2. Comply with all applicable laws (CFAA, Computer Misuse Act, etc.)
3. Never use against systems you do not own or have explicit permission to test

## Components

| Service | Port | Description |
|---|---|---|
| cai-service | 3201 | LLM AI orchestration (NVIDIA/OpenAI) |
| mhddos-service | 3301 | DDoS simulation engine |
| cloak-service | 3401 | Traffic cloaking & proxy chaining |
| c2-server | 3501 | C2 implant management (Sliver/Pupy) |
| phishing | 3502 | Phishing campaign manager (Gophish) |
| recon-pipeline | 3503 | Automated reconnaissance (Shodan/Spiderfoot) |
| sword | 3600 | Main orchestration engine |
| autonomous-brain | 3700 | AI decision engine & agent lifecycle |
| kali-tools | 3800 | Kali toolset wrapper (netexec, etc.) |
| raphael-api | 3900 | REST API gateway |
| tor-proxy | 9050 | Tor SOCKS5 proxy |
| neo4j | 7687 | Graph database (BloodHound) |
| sliver-server | 31337 | Sliver C2 server |
| caido | 48080 | Web proxy (Caido) |

## Development

```bash
# Run without Docker (Python 3.11+)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Start individual services manually
```

## License

See [LICENSE](LICENSE).
