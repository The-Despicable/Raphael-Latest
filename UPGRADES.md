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

## P7 — Security Hardening Before Real Use

Do NOT run this against real targets without:

- [ ] **All hardcoded credentials removed** (already fixed: sudo password, JWT_SECRET)
- [ ] **API key rotation** — the .env has what appear to be real NVIDIA/Ollama keys. Rotate before any operational use.
- [ ] **Tor enforcement cannot be bypassed** — remove `--no-anonymity` flag or require explicit confirmation + logging
- [ ] **IPv6 isolation** — add `sysctl net.ipv6.conf.all.disable_ipv6=1` to Dockerfiles, add ip6tables rules
- [ ] **Audit trail hardened** — current audit log is a JSONL file. Make it append-only via Docker volume permissions or ship to external syslog
- [ ] **No evidence on disk** — `brain.db`, `recon_log`, `audit/` all persist on Docker volumes. Add encryption-at-rest or shutdown wipe

---

## Implementation Order

| Phase | Items | Effort |
|-------|-------|--------|
| **1. Foundation** | P0 (phase executors), P4 (finding types), P3 (fix LLM loop in api.py) | 3-5 days |
| **2. Containers** | P1 (Dockerfiles), P2 (fix post-ex wrappers) | 2-3 days |
| **3. C2** | P5 (exfil), P6 (agent) | 3-4 days |
| **4. Hardening** | P7 (security) | 1-2 days |
| **Total** | | **~2 weeks** |

---

## Quick Wins (do these first, <2 hours each)

1. **`orchestrator/brain/api.py`: change the recon phase** to call `nmap_scanner.scan(target)` instead of `call_model()` — immediately switches from "LLM writes about ports" to "real port scan feeds next phase"

2. **`recon-pipeline/Dockerfile`: add `apt install -y whatweb subfinder`** — 1 line, immediately makes tech detection work in containers

3. **`orchestrator/postex/winrm_exploit.py`: wire credential flow** — it already has pywinrm, just needs credentials from the brain's finding store

4. **`.env.example: add missing vars** — `TOR_CONTROL_PASS`, `FROM_ADDR`, `TELEGRAM_TOKEN`, `C2_PSK` are read by code but undocumented
