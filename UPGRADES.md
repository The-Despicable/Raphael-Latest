# Raphael 2.0 — Necessary Upgrades

> Roadmap to turn this from an LLM prompt pipeline into an operational autonomous platform.

---

## P0 — Wire the Autonomous Loop to Real Tooling

**The single biggest gap.** `/v1/autonomous/start` (`orchestrator/brain/api.py:93-166`) runs a loop that calls `call_model()` for each phase and stores the LLM output. It never invokes a real scanner or exploit. The result is plausible-sounding text, not actual compromise.

### Fix: Replace `call_model()` with real phase executors

**`orchestrator/brain/api.py` — the phase loop (lines 129-163):**

```
for phase_name in phases:
    if phase_name == "recon":
        result = await run_recon(target)
    elif phase_name == "scan":
        result = await run_scan(target, open_ports)
    elif phase_name == "exploit":
        result = await run_exploit(target, vulns)
    ...
```

Each phase executor should:
1. Call the real tool wrapper (nmap, sqlmap, etc.)
2. Parse structured output (open ports, CVEs, credentials)
3. Store findings in memory for next phases
4. Let the LLM *analyze* results and suggest next steps — but never be the executor itself

### Phase Executors to create — `orchestrator/brain/phases/`

| File | What it does |
|------|-------------|
| `phases/__init__.py` | Phase registry + routing |
| `phases/recon.py` | Calls `nmap_scanner.scan()`, `whatweb_scanner.detect()`, stores open ports + tech stack |
| `phases/scan.py` | Calls `nuclei_scanner.scan()` on discovered ports, stores CVEs |
| `phases/exploit.py` | Calls `sqlmap_wrapper.exploit()` on SQL endpoints, `xss_scanner.scan()`, `ssrf_scanner.scan()` |
| `phases/postex.py` | Calls `winrm_exploit.py`, `bloodhound_integration.py`, attempts lateral movement |
| `phases/exfil.py` | Placeholder — needs real data exfiltation (see P2) |
| `phases/phish.py` | Calls GoPhish API or SMTP sender directly |

Each executor returns structured `PhaseResult`:

```python
@dataclass
class PhaseResult:
    phase: str
    success: bool
    findings: list[Finding]
    summary: str
    raw_output: str
    latency: float
```

The LLM then gets the structured findings as context for the *next* phase's strategy — it directs, it doesn't execute.

### Files to modify:
- `orchestrator/brain/api.py` — replace phase loop (lines 129-163)
- `orchestrator/brain/autonomous.py` — `execute_phase()` calls REST microservices instead of doing work locally. Either keep this pattern and fix microservices, or bypass them and call wrappers directly.

---

## P1 — Fix Docker Images to Ship Real Tools

Every service's Dockerfile is missing the actual attack tools. The wrappers exist and work when binaries are on PATH, but the containers don't have them.

### `recon-pipeline/Dockerfile`

Currently installs only Python packages and nmap. Add:

```dockerfile
# Already: nmap
RUN apt install -y whatweb subfinder nuclei
# Or download binaries:
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    && unzip nuclei_linux_amd64.zip && mv nuclei /usr/local/bin/
```

### `cai-service/Dockerfile`

Currently minimal. Needs:

```dockerfile
RUN pip install sqlmap  # or git clone /tmp/sqlmap into container
```

### `sword/Dockerfile`

Should have the full exploit toolkit the orchestrator's `orchestrator/exploit/` directory offers:
- sqlmap
- nuclei
- The Python exploit wrappers (ssrf_scanner.py, xss_scanner.py, payloads_db.py)

### `phishing/Dockerfile`

Needs GoPhish binary or at minimum the SMTP sender + email template engine.

### `postex/Dockerfile` (new or integrated into cai-service)

Needs pywinrm, bloodhound, and a real agent implant (not Pupy's broken setup).

### Files to modify:
- `recon-pipeline/Dockerfile`
- `cai-service/Dockerfile`
- `sword/Dockerfile`
- `phishing/Dockerfile`
- `brain/Dockerfile` (add sqlite3-backed vector index init)

---

## P2 — Replace Simulated Post-Exploitation with Real Implants

4 of 6 post-ex wrappers return `"status": "simulated"`.

### `orchestrator/postex/pupy_c2.py`

Currently checks for Pupy binary at `/tmp/pupy/pupy` — doesn't exist. Options:
1. Fix detection path and install Pupy properly in the Docker image
2. **Replace with a minimal Python agent** (simpler, more reliable):
   - 50-line reverse shell with AES encryption
   - File exfiltration via HTTP/SMTP/DNS
   - No external dependencies beyond stdlib + pycryptodome

### `orchestrator/postex/netexec_wrapper.py`

Same problem — binary not found. NetExec is Python-based, so `pip install netexec` in the Dockerfile is straightforward.

### `orchestrator/postex/winrm_exploit.py`

Already has `pywinrm` import — this one is close to working. Just needs proper credential management (feed from previous phases' findings).

### `orchestrator/postex/bloodhound_integration.py`

Works if Neo4j is accessible. The Docker Compose already has a `neo4j` service. Wire it:

```yaml
depends_on:
  neo4j:
    condition: service_healthy
```

### Files to modify:
- `orchestrator/postex/pupy_c2.py` — replace with minimal agent or fix binary path
- `orchestrator/postex/netexec_wrapper.py` — install netexec or fix path
- `orchestrator/postex/winrm_exploit.py` — wire credential flow from brain memory
- `docker-compose.yml` — add neo4j health check, add postex dependencies

---

## P3 — Fix the LLM-as-Executor Pattern Globally

The system uses LLM output as the attack itself in multiple places:

| File | Lines | Problem |
|------|-------|---------|
| `orchestrator/brain/api.py` | 129-163 | Phase loop stores LLM text as phase output |
| `orchestrator/modes/autonomous.py` | (entire) | Same pattern — LLM generates attack narrative |
| `orchestrator/brain/adaptive_brain.py` | ~450-490 | `autonomous_chain()` generates multi-phase LLM text |
| `orchestrator/evasion_techniques.py` | (entire 339 lines) | Generates elaborate prompt decoration about syscalls/hijacking — never actually executed |

### Fix pattern for each:

```
BEFORE:  output = await call_model(model, prompt)  → store output
AFTER:   findings = await execute_phase(phase, target)  → LLM analyzes findings → store analysis
```

The LLM's role should be:
1. **Analyze** structured findings from real tools
2. **Decide** which technique/target/payload to use next
3. **Generate** payloads/configs for real tools to execute
4. **Never** be the thing that produces the "attack result"

### Files to modify:
- `orchestrator/brain/api.py` (the phase loop)
- `orchestrator/brain/autonomous.py` (`run_autonomous_engagement`)
- `orchestrator/brain/adaptive_brain.py` (`autonomous_chain` method)
- `orchestrator/modes/autonomous.py` (if kept — may be obsoleted by brain API)
- `orchestrator/evasion_techniques.py` (remove or repurpose — 339 lines of prompt decoration)

---

## P4 — Structured Finding Types + Memory Integration

The brain's `NeuralMemory` stores episodic events as blobs. For the system to learn across engagements, findings need a structured schema.

### Create `orchestrator/brain/finding.py`:

```python
@dataclass
class Port:
    number: int
    protocol: str
    service: str
    banner: str | None

@dataclass
class Vulnerability:
    cve_id: str | None
    scanner: str  # "nuclei" | "sqlmap" | "xss_scanner" | etc.
    endpoint: str
    severity: str  # "critical" | "high" | "medium" | "low"
    description: str
    proof: str  # evidence/raw output
    exploited: bool
    payload_used: str | None

@dataclass
class Credential:
    service: str
    username: str
    password: str | None
    hash: str | None
    source: str  # "bruteforce" | "sqli" | "default_creds" | etc.

@dataclass
class Finding:
    type: str  # "port" | "vuln" | "cred" | "host"
    data: Port | Vulnerability | Credential | dict
    timestamp: float
    source_phase: str
```

### Modify `NeuralMemory` in `orchestrator/brain/neural_memory.py`:

- Add `store_finding(target, finding)` — writes structured findings to a separate SQLite table
- Add `get_findings(target, type=None)` — retrieves structured findings
- Add `get_exploit_chain(target)` — returns `target → open_ports → vulns → exploited → creds → lateral_moves`
- The `schema_registry.py` is already set up for payload validation — extend it to validate findings too

---

## P5 — C2 + Exfiltration (Currently Missing)

There is no working C2 channel or data exfiltration path.

### `orchestrator/c2_channel.py`

Already exists and is registered in `api.py:210`. But it's minimal. Needs:

- Agent heartbeat endpoint (`/v1/agent/beat`)
- Task queue (`/v1/agent/task/next`)
- Result submission (`/v1/agent/result`)
- Encrypted comms (AES-GCM + per-agent keys)

### Exfiltration

Create `orchestrator/exfil/`:

| File | What it does |
|------|-------------|
| `exfil/dns.py` | DNS tunneling via dnscrypt-proxy (already in stack) |
| `exfil/http.py` | HTTP/C2 POST exfil over Tor |
| `exfil/smtp.py` | Email exfil via SMTP (already configured) |
| `exfil/pipeline.py` | Chooses method based on findings + target environment |

---

## P6 — Container Runtime: Real Agent, Not Pupy

Create a lightweight Python agent (`agent/` at project root):

```
agent/
├── Dockerfile          # 5MB Alpine-based
├── agent.py            # Main loop: heartbeat → get task → exec → submit
├── modules/
│   ├── __init__.py
│   ├── shell.py        # Reverse shell (TCP/HTTP/WebSocket)
│   ├── exfil.py        # File upload, data collection
│   ├── lateral.py      # SSH/WMI/PSExec lateral movement
│   └── persistence.py   # Task persistence, cleanup
└── crypto.py            # AES-GCM session encryption
```

The Docker Compose already has `c2-server` as a service. Wire the agent to connect back to it.

---

## P7 — Proxy & Anonymity Layer Overhaul

The current proxy layer has 3 critical failure modes that make it unsafe for real use. The `proxy_guard.py` is a 1050+ line file that mixes genuine enforcement with theoretical prompt decoration — and the entire system has a kill switch (`--no-anonymity`) that bypasses everything silently.

### 7a — Kill `--no-anonymity` Bypass (HIGH)

The `--no-anonymity` flag is checked in **8 places** across the codebase. Every time it's `True`, the proxy guard logs `"BYPASSED (no_anonymity mode)"` and returns success without checking anything.

**Files to fix:**

| File | Line | What it does |
|------|------|-------------|
| `orchestrator/proxy_guard.py` | 202, 242, 308 | `__init__` stores `no_anonymity`, `check()` and `_route_through_tor()` return immediately if set |
| `orchestrator/brain/anonymity_guard.py` | 12, 86 | Passes `allow_skip` straight to `ProxyGuard(no_anonymity=True)` |
| `orchestrator/brain/api.py` | 41, 97, 110, 112, 177 | `start_autonomous` accepts and forwards `no_anonymity` |
| `orchestrator/modes/autonomous.py` | 237, 245, 247 | Same pattern |
| `orchestrator/app.py` | 66, 140, 416 | CLI parses `--no-anonymity` and logs to `anon_logger` (but does not abort) |
| `raphael_cli.py` | — | Not checked but likely has same pattern |

**Fix:**

```python
# In proxy_guard.py — remove the bypass path entirely:
def check(self):
    # Delete: if self._no_anonymity: return {"bypassed": True}
    # Always enforce:
    results = {}
    results["tor"] = self._check_tor()
    results["dns"] = self._check_dns_leak()
    results["ipv6"] = self._check_ipv6()
    ...
```

If the user needs a dev mode for local testing, gate it behind an environment variable (`RAPHAEL_DEV_MODE=1`) that logs a **critical warning to stderr** and requires `--confirm-dev-mode` CLI flag. One gate, not 8 independent checks.

### 7b — Fix DNS Leaks (HIGH)

`orchestrator/proxy_guard.py:697` uses hardcoded `1.1.1.1` and `8.8.8.8` for direct DNS resolution checks:

```python
# Line ~697 — DNS resolution bypasses Tor
def _check_dns_leak(self):
    for ns in ["1.1.1.1", "8.8.8.8"]:
        socket.create_connection((ns, 53), timeout=3)  # Direct UDP to Cloudflare/Google
```

This is a **test** that detects leaks, but the actual `socket` calls in the rest of the file may also bypass Tor if not using `socks5h://`. The fix:

1. Replace all raw `socket.create_connection` calls with Tor-routed connections (via `requests` with `proxies={"http": "socks5h://tor-proxy:9050", "https": "socks5h://tor-proxy:9050"}`)
2. Force DNS resolution through Tor by using `socks5h` (the `h` is critical — it routes DNS through the SOCKS proxy) instead of `socks5`
3. Remove the hardcoded DNS server tests that leak by connecting directly

### 7c — IPv6 Isolation (HIGH)

IPv6 is not blocked anywhere. The Docker containers inherit the host's IPv6 stack. If the host has IPv6, traffic can leak regardless of Tor/VPN.

**Fix in each Dockerfile:**

```dockerfile
RUN sysctl -w net.ipv6.conf.all.disable_ipv6=1
RUN ip6tables -P INPUT DROP && ip6tables -P OUTPUT DROP && ip6tables -P FORWARD DROP
```

Or in `docker-compose.yml` with `sysctls:`:

```yaml
services:
  autonomous-brain:
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
```

Add to every service that makes outbound connections: `recon-pipeline`, `cai-service`, `sword`, `phishing`, `exfil`, `autonomous-brain`, `cloak-service`.

### 7d — Tor Control Password Consistency (MEDIUM)

Two different env var names for the same thing:

| Var | Used by |
|-----|---------|
| `TOR_PASSWORD` | `.env.example`, `docker-compose.yml`, `cloak-service` |
| `TOR_CONTROL_PASS` | `proxy_guard.py:436`, `anonymity_guard.py:45`, `docker-compose.yml` |

`docker-compose.yml` sets `TOR_CONTROL_PASS` for the tor-proxy container. `anonymity_guard.py` reads `TOR_CONTROL_PASS`. But `.env.example` documents `TOR_PASSWORD`. This means anyone following the setup guide will have a broken Tor control connection.

**Fix:**
- Standardize on `TOR_CONTROL_PASS` everywhere (it's more descriptive)
- Update `.env.example` to use `TOR_CONTROL_PASS`
- Add a fallback: if `TOR_CONTROL_PASS` is empty, try reading `TOR_PASSWORD`

### 7e — Make the Kill Switch Scripts Work Inside Docker (MEDIUM)

`kill_switch.sh` and `kill_switch_status.sh` are shell scripts meant for the host, not the containers. The `docker-compose.yml` already has a `tor-proxy` service with proper network isolation. The kill switch should work at the container level:

```yaml
services:
  autonomous-brain:
    cap_add:
      - NET_ADMIN  # Already has this
    # Add iptables rules on container start:
    entrypoint: |
      sh -c "
        ip6tables -P OUTPUT DROP &&
        iptables -P OUTPUT DROP &&
        iptables -A OUTPUT -o lo -j ACCEPT &&
        iptables -A OUTPUT -d $$TOR_PROXY_IP -j ACCEPT &&
        exec python -m uvicorn orchestrator.brain.api:app --host 0.0.0.0 --port 3700
      "
```

This enforces at the container level: only loopback and Tor proxy are reachable. Everything else drops.

### 7f — ProxyGuard: Strip the Theater, Keep the Enforcement (LOW)

`orchestrator/proxy_guard.py` is 1050+ lines. Much of it is theoretical:

- `_simulate_mimicry()` — generates prompt text about browser fingerprinting, never actually executes
- `_analyze_traffic_pattern()` — describes traffic analysis techniques, doesn't implement them  
- Long docstrings about Tor design, DNS architecture, etc. (lines 450-550, 720-800)

These are prompt decoration for the LLM, not operational code. Strip them to ~300 lines of real enforcement:

| Keep (~300 lines) | Remove (~750 lines) |
|--------------------|--------------------|
| Tor connectivity check | Traffic analysis descriptions |
| DNS leak detection (via Tor) | Browser fingerprinting theory |
| IPv6 check | Network architecture essays |
| SOCKS5 routing | Tor design documentation |
| Credential management | Log analysis techniques |
| `check()` orchestrator | All `_simulate_*` methods |

### Files to modify:
- `orchestrator/proxy_guard.py` — strip theater, harden enforcement, standardize env vars
- `orchestrator/brain/anonymity_guard.py` — remove `allow_skip` passthrough
- `orchestrator/brain/api.py` — remove `no_anonymity` from `StartRequest`
- `orchestrator/app.py` — remove `--no-anonymity` CLI flag
- `orchestrator/modes/autonomous.py` — remove `no_anonymity` parameter
- `docker-compose.yml` — add `sysctls: net.ipv6.conf.all.disable_ipv6=1` to all services
- Each Dockerfile — add ip6tables rules or container-level kill switch
- `.env.example` — `TOR_PASSWORD` → `TOR_CONTROL_PASS`

---

## P8 — Security Hardening Before Real Use

Do NOT run this against real targets without:

- [ ] **All hardcoded credentials removed** (already fixed: sudo password, JWT_SECRET)
- [ ] **API key rotation** — the .env has what appear to be real NVIDIA/Ollama keys. Rotate before any operational use.
- [ ] **Tor enforcement cannot be bypassed** — `--no-anonymity` is removed (P7a)
- [ ] **IPv6 isolation** — `sysctl disable_ipv6=1` in Dockerfiles + ip6tables DROP (P7c)
- [ ] **No DNS leaks** — `socks5h://` everywhere, no direct socket.create_connection (P7b)
- [ ] **Audit trail hardened** — current audit log is a JSONL file. Make it append-only via Docker volume permissions or ship to external syslog
- [ ] **No evidence on disk** — `brain.db`, `recon_log`, `audit/` all persist on Docker volumes. Add encryption-at-rest or shutdown wipe
- [ ] **Container-level egress lockdown** — iptables DROP in each container, only Tor proxy allowed (P7e)

---

## Implementation Order

| Phase | Items | Effort |
|-------|-------|--------|
| **1. Foundation** | P0 (phase executors), P4 (finding types), P3 (fix LLM loop in api.py) | 3-5 days |
| **2. Proxy** | P7 (anonymity killswitches, DNS, IPv6, Tor control, container lockdown) | 2-3 days |
| **3. Containers** | P1 (Dockerfiles install tools), P2 (fix post-ex wrappers) | 2-3 days |
| **4. C2** | P5 (exfil), P6 (agent) | 3-4 days |
| **5. Hardening** | P8 (security checklist) | 1-2 days |
| **Total** | | **~3 weeks** |

---

## Quick Wins (do these first, <2 hours each)

1. **`orchestrator/brain/api.py`: change the recon phase** to call `nmap_scanner.scan(target)` instead of `call_model()` — immediately switches from "LLM writes about ports" to "real port scan feeds next phase"

2. **`recon-pipeline/Dockerfile`: add `apt install -y whatweb subfinder`** — 1 line, immediately makes tech detection work in containers

3. **`orchestrator/postex/winrm_exploit.py`: wire credential flow** — it already has pywinrm, just needs credentials from the brain's finding store

4. **`.env.example: fix `TOR_PASSWORD` → `TOR_CONTROL_PASS`** — 1 line, fixes Tor control connection for anyone following the setup guide

5. **`docker-compose.yml`: add `sysctls: net.ipv6.conf.all.disable_ipv6=1` to all services** — 1 line per service, plugs IPv6 leak

6. **`orchestrator/proxy_guard.py`: delete the `if self._no_anonymity: return` bypass** — 2 lines, removes the biggest OpSec hole
