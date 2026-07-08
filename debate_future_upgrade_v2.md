# Debate v2: Kimi + Gemma4 + Me — F1/F2 Worth It? Integration Plan

Generated: Wed Jul  8 10:44:29 2026

---

## Kimi Round 1 (Verdict + Plan)

### **Q1: Are these 2 additions worth it?**
**YES_WITH_MODIFICATIONS**

**Why?**
- **F1 (Multi-Agent AI)** transforms Raphael from a rigid, linear pentesting tool into a dynamic, adaptive red-team platform. This is a ** shift** it enables parallel recon/scan/exploit, cross-session learning, and custom test generation, which are table stakes for modern autonomous security tools.
- **F2 (CI/CD Integration)** delivers **immediate business value** by making Raphael usable in DevSecOps pipelines. Without this, Raphael remains a niche, interactive tool **not a product**.
- **However**, the prior critique correctly identifies **critical gaps** in security, stability, and validation. Without addressing these, Raphael 2.0 risks:
 - **Hallucinated or dangerous LLM outputs** (e.g., suggesting `rm -rf /` as a "test").
 - **Performance collapse** (unbounded memory, synchronous Neo4j writes).
 - **Command injection** (unsandboxed LLM-generated tool calls).
 - **Pipeline disruptions** (noisy scans triggering WAF/EDR alerts).
 - **Compliance violations** (lack of HITL approvals for high-risk actions).

**The modifications are non-negotiable.** With them, Raphael 2.0 becomes:
✅ **Competitive** (multi-agent autonomy + CI/CD gating).
✅ **Safe** (bounded memory, sandboxed execution, deterministic fallbacks).
✅ **Production-ready** (stealth controls, progress-based fault isolation).

---

### **Q2: Integration Plan**
#### **Guiding Principles**
1. **F2 (CI/CD) First** - Deliver immediate value and establish a hardened perimeter.
2. **Incremental Agent Rollout**, Start with `ReconAgent` and `ScanAgent` (low-risk), then add `ExploitAgent` and `PostExAgent` (high-risk).
3. **Defense in Depth** Every LLM-generated action is validated, sandboxed, and rate-limited.
4. **Observability**; Logging, metrics, and checkpointing for every agent.

---

## **Phase 1: CI/CD Integration (F2) - 12 Days**
*Goal: Harden the API, CLI, and pipeline templates before introducing agents.*

### **1. API Hardening (mTLS/OIDC, JWT, Input Validation, Scope Enforcement)**
**Files:**
- `orchestrator/api/server.py` (new)
- `orchestrator/api/middleware.py` (new)
- `orchestrator/api/schemas.py` (new)
- `orchestrator/api/dependencies.py` (new)
- `config/scope_schema.yaml` (new)
- `docker/api.Dockerfile` (modified)

**Implementation:**
#### **a. FastAPI Server with mTLS/OIDC**
```python
# orchestrator/api/server.py
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import ssl

app = FastAPI(title="Raphael CI API")
app.add_middleware(HTTPSRedirectMiddleware)  # Enforce TLS
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.raphael.ai"])  # Prevent host header attacks

# mTLS setup
ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_ctx.load_cert_chain("/etc/ssl/certs/raphael-api.crt", "/etc/ssl/private/raphael-api.key")
ssl_ctx.load_verify_locations(cafile="/etc/ssl/certs/ca-bundle.crt")

# OIDC/JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
bearer = HTTPBearer()

async def get_current_user(token: str = Security(oauth2_scheme)):
    credentials_exception = HTTPException(401, "Invalid authentication")
    try:
        payload = jwt.decode(token, "OIDC_PUBLIC_KEY", algorithms=["RS256"])
        return payload
    except jwt.PyJWTError:
        raise credentials_exception
```
**Priority:** P0
**LOC:** ~200
**Dependencies:** None

#### **b. Input Validation & Scope Enforcement**
```python
# orchestrator/api/schemas.py
from pydantic import BaseModel, constr, validator
from typing import Optional
import re

class CIEngageRequest(BaseModel):
    target: constr(strip_whitespace=True, min_length=3, max_length=255)
    phases: Optional[list[str]] = ["recon", "scan", "exploit", "postex"]
    depth: str = "standard"  # quick|standard|deep
    scope_file: Optional[str] = None  # Path to scope.yaml

    @validator("target")
    def validate_target(cls, v):
        if not re.match(r"^([a-zA-Z0-9\-\.\/]+|[a-zA-Z0-9\-\.]+)$", v):
            raise ValueError("Invalid target format")
        return v

# orchestrator/api/dependencies.py
from fastapi import Depends
from .schemas import CIEngageRequest

async def enforce_scope(req: CIEngageRequest):
    scope = load_scope_file(req.scope_file) if req.scope_file else DEFAULT_SCOPE
    if not is_target_in_scope(req.target, scope):
        raise HTTPException(403, "Target out of scope")
    return scope
```
**Priority:** P0
**LOC:** ~150
**Dependencies:** None

#### **c. Scope File Parser**
```yaml
# config/scope_schema.yaml
version: 1.0
engagement:
  target: "example.com"
  allowed_domains:
    - "*.example.com"
  allowed_ips:
    - "192.168.1.0/24"
  excluded:
    - "dev.example.com"
  depth: "standard"
  rate_limit: 2.0  # requests/sec
  business_hours_only: true
  notify:
    on_complete: "slack://#security"
    on_critical: "pagerduty://team-security"
```
**Priority:** P0
**LOC:** ~100 (YAML + parser)
**Dependencies:** `schemas.py`

#### **d. JWT Short-Lived Tokens**
```python
# orchestrator/api/auth.py
from datetime import datetime, timedelta
import jwt

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, "JWT_SECRET", algorithm="HS256")
```
**Priority:** P0
**LOC:** ~30
**Dependencies:** None

#### **e. CI/CD CLI Tool**
```python
# cli/raphael_ci.py
import click
import httpx
import os

@click.group()
def cli():
    pass

@cli.command()
@click.argument("target")
@click.option("--depth", default="standard")
@click.option("--scope-file", type=click.Path(exists=True))
def engage(target, depth, scope_file):
    api_key = os.getenv("RAPHAEL_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"}
    data = {"target": target, "depth": depth}
    if scope_file:
        with open(scope_file) as f:
            data["scope_file"] = f.read()
    resp = httpx.post("https://api.raphael.ai/v1/ci/engage", json=data, headers=headers)
    click.echo(resp.json())
```
**Priority:** P0
**LOC:** ~100
**Dependencies:** `server.py`

#### **f. Pipeline Templates**
```yaml
# .github/workflows/raphael-scan.yml
name: Raphael Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Raphael
        run: |
          pip install raphael-cli
          raphael-ci engage ${{ secrets.STAGING_URL }} --depth standard --scope-file .raphael-scope.yaml
        env:
          RAPHAEL_API_KEY: ${{ secrets.RAPHAEL_API_KEY }}
```
**Priority:** P1
**LOC:** ~50 (per template)
**Dependencies:** `cli/raphael_ci.py`

---

## **Phase 2: Multi-Agent Framework (F1) 30 Days**
*Goal: Build the agent framework with all safety mechanisms.*

### **2. Deterministic GoalTree Validation with Fallback**
**Files:**
- `orchestrator/agents/goal_tree.py` (new)
- `orchestrator/agents/validator.py` (new)
- `orchestrator/agents/orchestrator.py` (modified)

**Implementation:**
#### **a. GoalTree Schema**
```python
# orchestrator/agents/goal_tree.py
from pydantic import BaseModel, validator
from typing import List, Optional

class GoalNode(BaseModel):
    id: str
    description: str
    agent: str  # recon|scan|exploit|postex
    dependencies: List[str] = []
    max_attempts: int = 3
    timeout: int = 300
    fallback: Optional[str] = None  # ID of fallback goal

    @validator("agent")
    def validate_agent(cls, v):
        if v not in ["recon", "scan", "exploit", "postex"]:
            raise ValueError("Invalid agent type")
        return v
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** None

#### **b. GoalTree Validator**
```python
# orchestrator/agents/validator.py
from .goal_tree import GoalNode
from typing import List

class GoalTreeValidator:
    def __init__(self):
        self.valid_agents = ["recon", "scan", "exploit", "postex"]
        self.default_fallback = {
            "recon": "default_recon_sweep",
            "scan": "default_nmap_scan",
            "exploit": "skip_exploit",
            "postex": "skip_postex"
        }

    def validate(self, goal_tree: List[GoalNode]) -> bool:
        # Check for cycles
        visited = set()
        for node in goal_tree:
            if node.id in visited:
                return False
            visited.add(node.id)
            if not all(dep in [n.id for n in goal_tree] for dep in node.dependencies):
                return False
        return True

    def apply_fallback(self, goal_tree: List[GoalNode]) -> List[GoalNode]:
        validated_tree = []
        for node in goal_tree:
            if not self.validate([node]):
                fallback_id = node.fallback or self.default_fallback.get(node.agent)
                if fallback_id:
                    validated_tree.append(self.get_fallback_goal(fallback_id))
            else:
                validated_tree.append(node)
        return validated_tree

    def get_fallback_goal(self, goal_id: str) -> GoalNode:
        # Predefined safe fallbacks
        fallbacks = {
            "default_recon_sweep": GoalNode(
                id="default_recon_sweep",
                description="Passive DNS and WHOIS lookup",
                agent="recon"
            ),
            "default_nmap_scan": GoalNode(
                id="default_nmap_scan",
                description="nmap -sV --top-ports 100",
                agent="scan"
            )
        }
        return fallbacks.get(goal_id)
```
**Priority:** P0
**LOC:** ~150
**Dependencies:** `goal_tree.py`

#### **c. Orchestrator Integration**
```python
# orchestrator/agents/orchestrator.py
from .validator import GoalTreeValidator

class OrchestratorAgent:
    def __init__(self):
        self.validator = GoalTreeValidator()

    async def decompose(self, objective: str, target: str) -> List[GoalNode]:
        # LLM generates GoalTree
        llm_tree = await self.llm.generate_goal_tree(objective, target)
        # Validate and fallback
        validated_tree = self.validator.apply_fallback(llm_tree)
        return validated_tree
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** `validator.py`

---

### **3. Bounded, Async Memory (Neo4j + pgvector)**
**Files:**
- `orchestrator/agents/memory.py` (new)
- `orchestrator/agents/batch_writer.py` (new)
- `orchestrator/agents/schemas.py` (new)
- `docker/memory.Dockerfile` (new)

**Implementation:**
#### **a. Memory Store with Size Caps**
```python
# orchestrator/agents/memory.py
from neo4j import AsyncGraphDatabase
from pgvector.asyncpg import register_vector
import asyncio
import os

class AgentMemory:
    def __init__(self):
        self.neo4j_uri = os.getenv("NEO4J_URI")
        self.pgvector_uri = os.getenv("PGVECTOR_URI")
        self.max_embedding_batch = 100  # Batch pgvector writes
        self.max_neo4j_batch = 50  # Batch Neo4j writes
        self.neo4j_driver = AsyncGraphDatabase.driver(self.neo4j_uri)
        self.pgvector_pool = None  # Asyncpg connection pool

    async def initialize(self):
        self.pgvector_pool = await asyncpg.create_pool(self.pgvector_uri)
        await register_vector(self.pgvector_pool)

    async def store_finding(self, finding: dict, agent: str):
        # Batch embeddings
        if len(self.embedding_batch) >= self.max_embedding_batch:
            await self.flush_embeddings()
        self.embedding_batch.append(finding)

        # Batch Neo4j writes
        if len(self.neo4j_batch) >= self.max_neo4j_batch:
            await self.flush_neo4j()
        self.neo4j_batch.append((finding, agent))

    async def flush_embeddings(self):
        if not self.embedding_batch:
            return
        embeddings = [await self.generate_embedding(f) for f in self.embedding_batch]
        async with self.pgvector_pool.acquire() as conn:
            await conn.executemany(
                "INSERT INTO findings (embedding) VALUES ($1)",
                [(emb,) for emb in embeddings]
            )
        self.embedding_batch = []

    async def flush_neo4j(self):
        if not self.neo4j_batch:
            return
        async with self.neo4j_driver.session() as session:
            for finding, agent in self.neo4j_batch:
                await session.run(
                    """
                    MERGE (t:Target {ip: $ip})
                    MERGE (v:Vulnerability {cve: $cve})
                    MERGE (t)-[:HAS_VULNERABILITY {found_by: $agent}]->(v)
                    """,
                    ip=finding.get("ip"), cve=finding.get("cve"), agent=agent
                )
        self.neo4j_batch = []
```
**Priority:** P0
**LOC:** ~200
**Dependencies:** Neo4j, pgvector

#### **b. Background Batch Writer**
```python
# orchestrator/agents/batch_writer.py
import asyncio

class BatchWriter:
    def __init__(self, memory: AgentMemory):
        self.memory = memory
        self.write_interval = 10  # seconds

    async def start(self):
        while True:
            await asyncio.sleep(self.write_interval)
            await self.memory.flush_embeddings()
            await self.memory.flush_neo4j()
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** `memory.py`

---

### **4. MessageBus with Back-Pressure & Dead-Letter Queue**
**Files:**
- `orchestrator/agents/message_bus.py` (new)
- `orchestrator/agents/schemas.py` (new)

**Implementation:**
```python
# orchestrator/agents/message_bus.py
import asyncio
from typing import Dict, List, Callable, Any
from dataclasses import dataclass

@dataclass
class Message:
    sender: str
    recipient: str
    payload: Any
    priority: int = 0
    max_retries: int = 3

class MessageBus:
    def __init__(self):
        self.queues: Dict[str, asyncio.Queue] = {}
        self.dead_letter_queue = asyncio.Queue()
        self.max_queue_size = 1000  # Back-pressure
        self.livelock_threshold = 100  # Messages processed without progress

    async def send(self, msg: Message):
        if msg.recipient not in self.queues:
            self.queues[msg.recipient] = asyncio.Queue(maxsize=self.max_queue_size)
        try:
            await self.queues[msg.recipient].put(msg)
        except asyncio.QueueFull:
            await self.dead_letter_queue.put(msg)  # Back-pressure

    async def receive(self, agent: str, handler: Callable[[Message], Any]):
        if agent not in self.queues:
            return
        queue = self.queues[agent]
        processed = 0
        while processed < self.livelock_threshold:
            msg = await queue.get()
            try:
                await handler(msg)
                processed += 1
            except Exception as e:
                msg.max_retries -= 1
                if msg.max_retries <= 0:
                    await self.dead_letter_queue.put(msg)
                else:
                    await self.send(msg)  # Requeue
```
**Priority:** P0
**LOC:** ~150
**Dependencies:** None

---

### **5. Progress-Metric-Based Fault Isolation**
**Files:**
- `orchestrator/agents/progress.py` (new)
- `orchestrator/agents/base_agent.py` (modified)

**Implementation:**
```python
# orchestrator/agents/progress.py
from dataclasses import dataclass
from typing import Dict

@dataclass
class ProgressMetrics:
    tasks_completed: int = 0
    tasks_failed: int = 0
    bytes_exfiltrated: int = 0
    credentials_cracked: int = 0
    ports_scanned: int = 0
    last_update: float = 0  # Timestamp

class ProgressTracker:
    def __init__(self):
        self.metrics: Dict[str, ProgressMetrics] = {}

    def update(self, agent: str, **kwargs):
        if agent not in self.metrics:
            self.metrics[agent] = ProgressMetrics()
        for k, v in kwargs.items():
            setattr(self.metrics[agent], k, v)
        self.metrics[agent].last_update = time.time()

    def is_stuck(self, agent: str, threshold: int = 300) -> bool:
        if agent not in self.metrics:
            return False
        return (time.time() - self.metrics[agent].last_update) > threshold

    def get_progress(self, agent: str) -> float:
        # Example: ReconAgent progress = ports_scanned / 1000
        if agent == "recon":
            return min(self.metrics[agent].ports_scanned / 1000, 1.0)
        elif agent == "scan":
            return min(self.metrics[agent].tasks_completed / 10, 1.0)
        return 0.0
```
**Priority:** P0
**LOC:** ~100
**Dependencies:** None

#### **Integration into BaseAgent**
```python
# orchestrator/agents/base_agent.py
from .progress import ProgressTracker

class BaseAgent:
    def __init__(self):
        self.progress = ProgressTracker()

    async def run(self, task: dict):
        while not self.progress.is_stuck(self.name):
            # Execute task
            self.progress.update(self.name, tasks_completed=1)
            await asyncio.sleep(1)
```
**Priority:** P0
**LOC:** ~20
**Dependencies:** `progress.py`

---

### **6. Sandbox for LLM-Generated Test Code**
**Files:**
- `orchestrator/agents/sandbox.py` (new)
- `docker/sandbox.Dockerfile` (new)

**Implementation:**
#### **a. gVisor Sandbox**
```python
# orchestrator/agents/sandbox.py
import subprocess
import tempfile
import os

class Sandbox:
    def __init__(self):
        self.sandbox_binary = "/usr/bin/runsc"

    def run(self, code: str, timeout: int = 10) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py") as f:
            f.write(code)
            f.flush()
            cmd = [self.sandbox_binary, "do", "--file-access=exclusive", f.name]
            try:
                result = subprocess.run(
                    cmd,
                    timeout=timeout,
                    capture_output=True,
                    text=True
                )
                return result.stdout
            except subprocess.TimeoutExpired:
                return "Sandbox timeout"
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** gVisor

#### **b. Docker Sandbox (Fallback)**
```dockerfile
# docker/sandbox.Dockerfile
FROM python:3.11-slim
RUN useradd -m sandboxuser
USER sandboxuser
WORKDIR /sandbox
# Restrict syscalls (seccomp)
COPY seccomp.json /etc/seccomp.json
```
**Priority:** P0
**LOC:** ~20
**Dependencies:** None

---

### **7. Stealth/Noise-Budget Mechanism**
**Files:**
- `orchestrator/agents/stealth.py` (new)
- `orchestrator/agents/base_agent.py` (modified)

**Implementation:**
```python
# orchestrator/agents/stealth.py
from dataclasses import dataclass
import time

@dataclass
class StealthBudget:
    max_requests_per_minute: int = 60
    max_parallel_scans: int = 5
    current_requests: int = 0
    last_request_time: float = 0

    def can_scan(self) -> bool:
        now = time.time()
        if now - self.last_request_time > 60:
            self.current_requests = 0
            self.last_request_time = now
        if self.current_requests >= self.max_requests_per_minute:
            return False
        self.current_requests += 1
        return True
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** None

#### **Integration into BaseAgent**
```python
# orchestrator/agents/base_agent.py
from .stealth import StealthBudget

class BaseAgent:
    def __init__(self):
        self.stealth = StealthBudget()

    async def run_tool(self, tool: str, args: list):
        if not self.stealth.can_scan():
            await asyncio.sleep(60)
        # Execute tool
```
**Priority:** P0
**LOC:** ~20
**Dependencies:** `stealth.py`

---

### **8. HITL Approval Gates + State Checkpointing**
**Files:**
- `orchestrator/agents/hitl.py` (new)
- `orchestrator/agents/checkpoint.py` (new)

**Implementation:**
#### **a. HITL Approval**
```python
# orchestrator/agents/hitl.py
from fastapi import WebSocket
import json

class HITLGateway:
    def __init__(self):
        self.pending_approvals = {}

    async def request_approval(self, action: str, agent: str) -> bool:
        # Send to WebSocket endpoint
        async with websockets.connect("ws://api.raphael.ai/hitl") as ws:
            await ws.send(json.dumps({"action": action, "agent": agent}))
            response = await ws.recv()
            return json.loads(response)["approved"]
```
**Priority:** P1
**LOC:** ~50
**Dependencies:** FastAPI WebSockets

#### **b. State Checkpointing**
```python
# orchestrator/agents/checkpoint.py
import pickle
import os

class Checkpoint:
    def __init__(self, checkpoint_dir: str = "/checkpoints"):
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(self.checkpoint_dir, exist_ok=True)

    def save(self, agent: str, state: dict):
        with open(f"{self.checkpoint_dir}/{agent}.pkl", "wb") as f:
            pickle.dump(state, f)

    def load(self, agent: str) -> dict:
        try:
            with open(f"{self.checkpoint_dir}/{agent}.pkl", "rb") as f:
                return pickle.load(f)
        except FileNotFoundError:
            return {}
```
**Priority:** P1
**LOC:** ~50
**Dependencies:** None

---

### **9. Agent Loop Iteration Caps + Heartbeat**
**Files:**
- `orchestrator/agents/base_agent.py` (modified)

**Implementation:**
```python
# orchestrator/agents/base_agent.py
class BaseAgent:
    def __init__(self):
        self.max_iterations = 1000  # Prevent infinite loops
        self.heartbeat_interval = 30  # seconds

    async def run(self, task: dict):
        iterations = 0
        last_heartbeat = time.time()
        while iterations < self.max_iterations:
            # Check heartbeat
            if time.time() - last_heartbeat > self.heartbeat_interval:
                self.send_heartbeat()
                last_heartbeat = time.time()

            # Execute task
            iterations += 1
            await asyncio.sleep(1)
```
**Priority:** P0
**LOC:** ~20
**Dependencies:** None

---

### **10. Least-Privilege Agent Roles**
**Files:**
- `orchestrator/agents/roles.py` (new)
- `docker/agent.Dockerfile` (modified)

**Implementation:**
#### **a. Role Definitions**
```python
# orchestrator/agents/roles.py
from dataclasses import dataclass

@dataclass
class AgentRole:
    name: str
    allowed_tools: list  # e.g., ["nmap", "subfinder"]
    network_access: str  # "read-only", "full"
    filesystem_access: str  # "none", "read-only", "read-write:/tmp"

ROLES = {
    "recon": AgentRole(
        name="recon",
        allowed_tools=["nmap", "subfinder", "whatweb"],
        network_access="read-only",
        filesystem_access="none"
    ),
    "scan": AgentRole(
        name="scan",
        allowed_tools=["nuclei", "nikto"],
        network_access="full",
        filesystem_access="read-only:/tmp"
    ),
    "exploit": AgentRole(
        name="exploit",
        allowed_tools=["sqlmap", "metasploit"],
        network_access="full",
        filesystem_access="read-write:/tmp"
    ),
    "postex": AgentRole(
        name="postex",
        allowed_tools=["sliver", "impacket"],
        network_access="full",
        filesystem_access="read-write:/tmp"
    )
}
```
**Priority:** P0
**LOC:** ~50
**Dependencies:** None

#### **b. Docker Profiles per Role**
```dockerfile
# docker/agent.Dockerfile
FROM python:3.11-slim

# ReconAgent (read-only network)
ARG ROLE=recon
RUN if [ "$ROLE" = "recon" ]; then \
        apt-get install -y nmap subfinder && \
        chmod -R 500 /usr/bin/nmap; \
    fi

# ScanAgent (firewall rules)
RUN if [ "$ROLE" = "scan" ]; then \
        iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT && \
        iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT && \
        iptables -A OUTPUT -j DROP; \
    fi
```
**Priority:** P0
**LOC:** ~30
**Dependencies:** None

---

## **Integration Plan Summary**
| **Phase** | **Task** | **Files** | **LOC** | **Priority** | **Dependencies** | **Effort (Days)** |
|-----------|----------|-----------|---------|--------------|------------------|-------------------|
| **Phase 1** | CI/CD Hardening | `api/server.py`, `api/schemas.py`, `cli/raphael_ci.py` | ~650 | P0 | None | 8 |
| **Phase 1** | Scope Enforcement | `config/scope_schema.yaml`, `api/dependencies.py` | ~100 | P0 | `api/schemas.py` | 2 |
| **Phase 1** | Pipeline Templates | `.github/workflows/`, `Jenkinsfile` | ~150 | P1 | `cli/raphael_ci.py` | 2 |
| **Phase 2** | Agent Framework | `agents/base_agent.py`, `agents/message_bus.py` | ~300 | P0 | None | 5 |
| **Phase 2** | GoalTree Validation | `agents/goal_tree.py`, `agents/validator.py` | ~200 | P0 | `agents/base_agent.py` | 3 |
| **Phase 2** | Bounded Memory | `agents/memory.py`, `agents/batch_writer.py` | ~300 | P0 | Neo4j, pgvector | 4 |
| **Phase 2** | Progress Metrics | `agents/progress.py` | ~100 | P0 | `agents/base_agent.py` | 2 |
| **Phase 2** | Sandboxing | `agents/sandbox.py`, `docker/sandbox.Dockerfile` | ~100 | P0 | gVisor | 3 |
| **Phase 2** | Stealth Controls | `agents/stealth.py` | ~50 | P0 | `agents/base_agent.py` | 2 |
| **Phase 2** | HITL + Checkpointing | `agents/hitl.py`, `agents/checkpoint.py` | ~100 | P1 | FastAPI WebSockets | 3 |
| **Phase 2** | Roles | `agents/roles.py`, `docker/agent.Dockerfile` | ~80 | P0 | None | 2 |
| **Phase 2** | REPL Integration | `raphael_cli.py` | ~100 | P1 | All Phase 2 | 3 |
| **Total** | | | **~2,230** | | | **39** |

---

## **Rollout Plan**
1. **Week 1-2**: Deploy hardened CI/CD API (F2).
 - Validate scope enforcement, mTLS, and pipeline integrations.
 - Gather feedback from DevSecOps teams.

2. **Week 3-7**: Roll out multi-agent framework (F1) incrementally.
 - Start with `ReconAgent` and `ScanAgent` (low-risk).
 - Add `ExploitAgent` only after sandboxing is proven.
 - Enable `PostExAgent` last (highest risk).

3. **Week 8**: Full regression testing.
 - Validate all safety mechanisms (sandbox, memory, progress).
 - Simulate noisy networks, stuck agents, and LLM hallucinations.

4. **Week 9**: GA release.
 - Monitor for stability, stealth compliance, and CI/CD adoption.

---

## **Final Notes**
- **Security is not optional.** Every LLM-generated action must be validated, sandboxed, and rate-limited.
- **CI/CD is the priority.** F2 delivers immediate value and establishes a hardened perimeter.
- **Agents are incremental.** Start with read-only agents, then add write capabilities once safety is proven.
- **Observability is key.** Log every agent action, memory write, and network request.

**With these modifications, Raphael 2.0 becomes:**
✅ **Safe** (LLM outputs validated, sandboxed, and rate-limited).
✅ **Stable** (bounded memory, progress-based fault isolation).
✅ **Production-ready** (stealth controls, HITL approvals, CI/CD gating).

---

## Gemma4 Round 1 (Verdict + Plan)

## Q1: Are these 2 additions worth it?

**YES_WITH_MODIFICATIONS.**

The current version of Raphael is a linear tool; F1 and F2 transform it into a platform. F2 (CI/CD) provides immediate commercial viability by turning a manual tool into a security gate. F1 (Multi-Agent) solves the "brittleness" of deterministic pipelines, allowing Raphael to when it finds an unexpected entry point. However, the original proposal was "AI-optimistic" and ignored the catastrophic risks of command injection, LLM hallucinations, and resource exhaustion. Without the modifications detailed in the prior critique, F1 would be a liability (potentially crashing target systems or the host) and F2 would be a massive security hole (unauthenticated RCE via API). Implementing them with the required guardrails makes Raphael a top-tier autonomous security platform.

---

## Q2: Detailed Integration Plan

Following the recommended order, we implement **F2 (The Perimeter)** first to establish a secure gateway, then **F1 (The Brain)** to provide the intelligence.

### Phase 1: F2, Hardened CI/CD Gateway (Days 1-15)

**Goal:** Establish a secure, headless API that enforces scope and identity before any tool is touched.

| Item | Requirement | Implementation Details | Path / Signature | LoC | Pri | Dep |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **6.1** | **API Hardening** | Implement FastAPI middleware for OIDC/JWT validation and mTLS check. | `orchestrator/api/auth.py` <br> `def verify_jwt(token: str) -> UserPrincipal` | 150 | P0 | - |
| **6.2** | **Scope Enforcement** | A validator that checks `target` and `allowed_domains` against a signed scope file before passing to the brain. | `orchestrator/api/scope.py` <br> `class ScopeGuard: def validate_target(self, target: str, scope_file: Path) -> bool` | 100 | P0 | 6.1 |
| **6.3** | **Input Sanitization** | Strict regex validation for IP/Domain inputs to prevent shell injection in downstream Kali tools. | `orchestrator/api/utils.py` <br> `def sanitize_target(target: str) -> str` | 50 | P0 | - |
| **6.4** | **Headless API** | FastAPI endpoints for `/engage` and `/report` wiring into existing `brain/executor.py`. | `orchestrator/api/main.py` <br> `app = FastAPI()` | 300 | P1 | 6.2 |
| **6.5** | **CI CLI Tool** | Python Click app for pipeline integration. | `cli/raphael_ci.py` <br> `def run_engage(target, depth)` | 200 | P1 | 6.4 |

---

### Phase 2: F1 Multi-Agent Architecture (Days 16-55)

**Goal:** Replace the linear pipeline with a validated, sandboxed agent swarm.

#### A. The Foundation (Messaging & Memory)
| Item | Requirement | Implementation Details | Path / Signature | LoC | Pri | Dep |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **3.1** | **Hardened MessageBus** | Async queue with `maxsize` (back-pressure), a `dead_letter_queue` for failed tasks, and schema validation via Pydantic. | `orchestrator/bus.py` <br> `class MessageBus: async def publish(self, topic: str, msg: BaseMessage)` | 250 | P0 | - |
| **2.1** | **Bounded Async Memory** | Wrapper for Neo4j/pgvector using `asyncio.Queue` for batch writes and a `max_entities` cap to prevent OOM. | `orchestrator/memory.py` <br> `class AgentKnowledge: async def batch_store(self, findings: list[Finding])` | 300 | P0 | - |
| **10.1** | **Least-Privilege Roles** | Define `AgentRole` enums mapping to specific Linux users/Docker profiles (e.g., `RECON` $\rightarrow$ no-write access). | `orchestrator/roles.py` <br> `class AgentRole(Enum): RECON, SCAN, EXPLOIT, POSTEX` | 80 | P1 | - |

#### B. The Orchestration Loop
| Item | Requirement | Implementation Details | Path / Signature | LoC | Pri | Dep |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1** | **GoalTree Validation** | LLM generates JSON; a deterministic validator checks for required fields. If invalid, falls back to `DefaultReconPlan`. | `orchestrator/planner.py` <br> `def validate_goal_tree(tree: GoalTree) -> bool` | 150 | P0 | 3.1 |
| **8.1** | **HITL Approval Gates** | A state-machine check for "High Risk" actions (e.g., `exploit`). Pauses agent and sends signal to `raphael_cli.py` for user $Y/N$. | `orchestrator/agents/base.py` <br> `async def request_approval(self, action: Action) -> bool` | 120 | P1 | 3.1 |
| **8.2** | **State Checkpointing** | Serialization of the current `GoalTree` and `AgentMemory` to disk every 10 minutes for crash recovery. | `orchestrator/state.py` <br> `def save_checkpoint(eid: str, state: EngagementState)` | 100 | P2 | 2.1 |
| **9.1** | **Loop Caps & Heartbeat** | `BaseAgent` implements a `max_iterations` counter and a `heartbeat` timestamp to detect zombie agents. | `orchestrator/agents/base.py` <br> `class BaseAgent: self.iterations: int = 0` | 60 | P0 | - |

#### C. Execution & Safety
| Item | Requirement | Implementation Details | Path / Signature | LoC | Pri | Dep |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **5.1** | **Code Sandbox** | LLM-generated Python tests are wrapped in a gVisor/Docker container with no network access except to the target. | `orchestrator/sandbox.py` <br> `async def run_sandboxed_code(code: str, target: str) -> str` | 200 | P0 | 10.1 |
| **4.1** | **Metric Fault Isolation** | Instead of `time.sleep()`, agents track `bytes_sent` or `attempts_count`. If metrics plateau, the task is marked "Stuck". | `orchestrator/agents/base.py` <br> `def check_progress(self, metrics: ProgressMetrics) -> bool` | 120 | P1 | 9.1 |
| **7.1** | **Stealth/Noise Budget** | A global `NoiseController` that monitors WAF 403s/429s and injects `asyncio.sleep()` into `ScanAgent` and `ReconAgent`. | `orchestrator/stealth.py` <br> `class NoiseController: def get_delay(self) -> float` | 150 | P1 | 3.1 |

### Wiring into Existing Codebase

1. **`raphael_cli.py` $\rightarrow$ `orchestrator/api/main.py`**: The CLI no longer calls the brain directly for agent-mode; it sends a request to the API, which triggers the `OrchestratorAgent`.
2. **`brain/executor.py` $\rightarrow$ `orchestrator/agents/base.py`**: The old deterministic `PhaseExecutor` is deprecated. The new `BaseAgent` uses the `MessageBus` to communicate findings instead of returning a flat list to the REPL.
3. **`GrowthDB` $\rightarrow$ `orchestrator/memory.py`**: The SQLite flat file is replaced by the `AgentKnowledge` class, providing a unified interface for Neo4j (relational) and pgvector (semantic) storage.
4. **`Kali Tools API` $\rightarrow$ `orchestrator/sandbox.py`**: All tool calls generated by the `ExploitAgent` must pass through the `run_sandboxed_code` wrapper before hitting the `localhost:3800` tool API.

---

## Me (Assistant) Round 1

## My Judgement: YES_WITH_MODIFICATIONS

### Q1: Worth it?
Yes, but with a critical reordering. F2 (CI/CD) should be built FIRST as a thin wrapper around the existing phase engine. It's lower risk, delivers immediate value (security gating in pipelines), and establishes the API/auth/scope infrastructure that F1 will need anyway. F1 (Multi-Agent) is the long-term differentiator but should be built incrementally — start with just an Orchestrator that delegates to existing phase executors, then add specialist agents one at a time.

The prior critique's 55-day estimate is reasonable but can be front-loaded: F2 in ~10 days, then F1 phased over ~45 days with working milestones at each phase.

### Q2: Detailed Integration Plan

#### Phase 0 — Foundation (Days 1-3, P0)
**Goal:** No new capabilities, just the hooks both F1 and F2 need.

| File | Action | Detail |
|------|--------|--------|
| `orchestrator/events.py` | CREATE | EventBus class from UPGRADES.md P11e. Single `asyncio.Queue` per subscriber with maxsize. Events: `phase_start`, `phase_done`, `finding`, `error`, `agent_progress` |
| `orchestrator/auth.py` | CREATE | API key loading from env, SHA256 hashing, scope checking. Support `RAPHAEL_KEY_*` env vars. Scopes: admin, operator, viewer, agent |
| `orchestrator/scope.py` | CREATE | `AllowedScope` dataclass with `allows_domain()`, `allows_ip()`, `check(target)`. Read from `raphael-scope.yml` |
| `orchestrator/sandbox.py` | CREATE | `PatchSandbox` — runs any code string in `docker run --network=none --read-only --memory=256m --cpus=0.5 python:3.11-slim` with 30s timeout. Returns stdout/stderr/returncode |

**Integration points:**
- `raphael_cli.py`: import EventBus, emit events from all existing commands
- `brain/api.py`: add auth dependency to all endpoints

#### Phase 1 — F2: CI/CD API (Days 4-10, P0)
**Goal:** Headless API that wraps existing phase engine, usable from any CI pipeline.

| File | Action | Detail |
|------|--------|--------|
| `orchestrator/api/ci.py` | CREATE | FastAPI app: `POST /v1/ci/engage`, `GET /v1/ci/engage/{id}`, `GET /v1/ci/report/{id}`, `GET /v1/ci/health`. Each endpoint wraps existing `autonomous.handle()` or phase executors. Auth via `orchestrator/auth.py` |
| `orchestrator/api/quickci.py` | CREATE | Quick-scan endpoint: `POST /v1/ci/scan` — runs recon+scan phases synchronously, returns findings as JSON. No engagement tracking needed |
| `cli/raphael_ci.py` | CREATE | Click-based CLI: `raphael-ci engage run <target>`, `raphael-ci engage status <id>`, `raphael-ci report <id> --format json|sarif|junit`. Uses httpx to call API |
| `docker/api.Dockerfile` | CREATE | Lightweight Dockerfile: `FROM python:3.11-slim`, copy api/, expose 3999 |
| `docker-compose.yml` | MODIFY | Add `raphael-api` service on port 3999, depends on kali-tools + tor-proxy, env `RAPHAEL_MODE=headless` |
| `.github/workflows/raphael-pentest.yml` | CREATE | GH Actions template |
| `.gitlab-ci.yml` | CREATE | GitLab CI template |
| `orchestrator/webhook.py` | CREATE | Webhook delivery: POST results to configured URL, HMAC-signed payload, retry 3x with backoff |

**Wiring into existing code:**
- `orchestrator/brain/api.py` → `ci.py` imports `start_autonomous` from brain API, wraps it with auth + scope check
- `orchestrator/modes/autonomous.py` → `ci.py` calls `handle()` directly via import (no HTTP loopback)
- Result: `curl -H "Bearer $KEY" -X POST http://localhost:3999/v1/ci/engage -d '{"target":"10.0.1.0/24"}'` works

**Gate for Phase 2:** CI/CD pipeline successfully blocks a deployment with critical findings.

#### Phase 2 — F1a: Agent Framework (Days 11-20, P0)
**Goal:** Base agent infrastructure, OrchestratorAgent, wire into REPL.

| File | Action | Detail |
|------|--------|--------|
| `orchestrator/agents/__init__.py` | CREATE | Package init |
| `orchestrator/agents/base.py` | CREATE | `BaseAgent`: `name`, `system_prompt`, `tools`, `max_iterations=50`, `heartbeat_interval=30`. Lifecycle: `run(task, context) → Result`. Calls `self.think()` → `self.execute()` → `self.bus.emit()`. Stops after `max_iterations` or `should_terminate()` |
| `orchestrator/agents/bus.py` | CREATE | `MessageBus`: per-subscriber `asyncio.Queue(maxsize=1000)`. `publish(topic, msg)` → fan-out to subscribers. `DeadLetterQueue` for unhandled messages after 3 retries. `livelock_detector`: if agent emits >50 events/min with zero state change, flag it |
| `orchestrator/agents/orchestrator.py` | CREATE | `OrchestratorAgent(BaseAgent)`: `decompose(objective, target) → GoalTree`. GoalTree has `validate()` method that checks: (1) target is in scope, (2) each leaf maps to an existing tool, (3) no circular dependencies. If validation fails → fall back to `GoalTree.recon_sweep(target)` (hardcoded safe default). `tick()`: check progress, detect stuck subtasks (via progress metrics not just timeouts), replan |
| `orchestrator/agents/memory.py` | CREATE | `AgentMemory`: three backends with bounded writes. `EpisodicStore` (SQLite, capped at 100k events, auto-prune). `SemanticStore` (pgvector, batch embeddings every 10 findings or 30s, never inline). `GraphStore` (Neo4j, async writes via background worker, retry with exponential backoff on failure). `store_finding()` returns immediately — writes are queued |
| `orchestrator/agents/supervisor.py` | CREATE | `AgentSupervisor`: monitors heartbeats. If no heartbeat for 60s → restart agent. If same agent restarts >3 times in 300s → escalate to HITL. If agent in livelock (bus.detect_livelock()) → kill and spawn alternative |

**Wiring into existing code:**
- `raphael_cli.py`: add `/agent-engage <target>` command. Creates OrchestratorAgent, runs `decompose()`, then `tick()` loop with Live dashboard
- `orchestrator/providers.py`: no changes yet (agents use existing `call_model()`)
- No changes to phase executors yet — OrchestratorAgent starts by calling existing `ReconExecutor`, `ScanExecutor`, etc.

**Gate for Phase 3:** `/agent-engage` successfully runs a full engagement with Orchestrator delegating to existing phase executors.

#### Phase 3 — F1b: Specialist Agents (Days 21-35, P1)
**Goal:** Replace phase executors with true AI agents one at a time.

| File | Action | Detail |
|------|--------|--------|
| `orchestrator/agents/recon.py` | CREATE | `ReconAgent(BaseAgent)`: tools = web_search, fetch_url, DNS, whatweb, subfinder, nmap. System prompt: OSINT analyst persona. Runs in parallel with ScanAgent |
| `orchestrator/agents/scan.py` | CREATE | `ScanAgent(BaseAgent)`: tools = nuclei, nmap scripts, nikto, gobuster, FFuF, SQLi/XSS probes. Receives findings from ReconAgent via bus, prioritizes scan targets |
| `orchestrator/agents/exploit.py` | CREATE | `ExploitAgent(BaseAgent)`: tools = sqlmap, Metasploit, hydra, plus code generation. ALL generated code MUST go through `sandbox.py` first. No direct execution of LLM output. Sandbox returns stdout/stderr + returncode; agent only sees those |
| `orchestrator/agents/postex.py` | CREATE | `PostExAgent(BaseAgent)`: tools = Sliver C2, impacket, bloodhound, certipy. HITL gate before any agent deployment or lateral movement |

**Stealth integration:**
- `orchestrator/opsec_jitter.py` (already defined in UPGRADES.md P18d): wrap all agent tool calls
- `orchestrator/noise_budget.py`: per-target token bucket, max 2 req/s for scanning, 0.1 req/s for auth attempts. Agents check budget before each tool call. If budget exhausted → agent warns "rate limited" and waits

**HITL gates:**
- `orchestrator/hitl.py`: `HITLGate(prompt, timeout=300) → approved/rejected/timeout`. Prints prompt to CLI, waits for Y/N input. If timeout → reject (safe default). Wired into ExploitAgent (before exploit), PostExAgent (before agent deploy + lateral move)

**State checkpointing:**
- `orchestrator/agents/checkpoint.py`: after each finding, serializes full GoalTree + all findings to `checkpoints/{engagement_id}/{timestamp}.json`. On restart: `OrchestratorAgent.resume(checkpoint_path)` restores tree, reconnects bus, resumes in-flight tasks

**Wiring into existing code:**
- `orchestrator/brain/phases/` — can be deprecated once all specialist agents exist. But keep as deterministic fallback (agents call executors internally)
- `orchestrator/providers.py` — add rate limit check before each `call_model()`
- `orchestrator/evasion_techniques.py` — no changes, agents call it as tool

**Gate for Phase 4:** Specialist agents complete a full kill chain against a test target without human intervention (except HITL gates).

#### Phase 4 — Hardening + Polish (Days 36-55, P1/P2)

| Item | Files | Days | Priority |
|------|-------|------|----------|
| CI/CD API hardening | `orchestrator/api/ci.py`: add rate limiting, request validation (pydantic), audit logging | 2 | P1 |
| Memory tuning | `orchestrator/agents/memory.py`: benchmark Neo4j write latency, tune batch sizes, add connection pooling | 2 | P2 |
| GoalTree validation improvements | `orchestrator/agents/orchestrator.py`: add more fallback strategies based on real engagement data | 3 | P1 |
| Documentation | `docs/ci-cd.md`, `docs/agent-architecture.md`, `docs/scope-file.md` | 2 | P2 |
| Kill chain tests | `tests/test_agent_kill_chain.py`: validate full multi-agent flow against vulnu-lab | 3 | P0 (must pass before declaring done) |

### Key Trade-offs

1. **Neo4j vs. skip it**: Neo4j adds real value for attack path visualization but is heavy. SKIP in v1. Use GrowthDB (SQLite) for episodic + findings. Add Neo4j in Phase 4 only if queries actually need graph traversal. pgvector is same: skip in v1, add if semantic search proves valuable.

2. **Full sandbox vs. no sandbox**: The prior critique is right — unsandboxed LLM-generated code is dangerous. But `docker run --rm` on every exploit attempt adds 500ms+ latency. Compromise: cache warm containers, or use gVisor (faster than Docker for short-lived processes). Implement in Phase 3 when ExploitAgent ships.

3. **Async message bus vs. direct calls**: The bus adds complexity. For v1, use simple `asyncio.Queue` pairs between agents (Orchestrator has one queue per agent). Upgrade to proper pub/sub if >3 agents exist. Don't over-engineer upfront.

### What to Skip (v1)

- Neo4j knowledge graph (add later if needed)
- Full pgvector integration (Use GrowthDB's simple SQLite with keyword search)
- mTLS/OIDC for API (Start with Bearer tokens + API key rotation endpoint. Add OIDC if enterprise customers need SSO)
- Multi-hop SOCKS chaining (Out of scope for F1)
- Agent-to-agent negotiation (Keep it simple: Orchestrator → specialist, no peer-to-peer)


---

## Kimi Round 2 (Refinement)

{
 "agreement": [
 "Both F1 (Multi‑Agent AI) and F2 (CI/CD Integration) are worthwhile, but only with substantial safety and engineering modifications.",
 "F2 should be delivered first (or at least before the high‑risk parts of F1) to provide immediate DevSecOps value and to establish a hardened perimeter that F1 will rely on.",
 "Essential security controls are required across the board: strong API authentication (OIDC/JWT/mTLS), strict input validation/sanitization, scope enforcement, least‑privilege execution, and observability (logging, metrics, checkpointing, tracing).",
 "Any LLM‑generated code or tool invocation must run in a sandbox with resource limits and be validated before execution.",
 "An incremental, risk‑based rollout of agents is preferred to a big‑bang replacement.",
 "A resilient messaging/queuing system with back‑pressure, dead‑letter handling, and schema validation is needed.",
 "Memory/storage usage must be bounded (e.g., max entities, capped event stores) to prevent OOM.",
 "Human‑in‑the‑loop (HITL) approval gates are required for high‑risk actions such as exploitation.",
 "State checkpointing and heartbeat/livelock detection are necessary for crash recovery and agent health monitoring."
 ],
 "disagreement": [
 {
 "point": "Foundational work before building the CI/CD API or agent framework",
 "my_view": "Create a explicit Phase 0 (≈3 days) that builds shared primitives: an EventBus, API‑key/auth helper, AllowedScope dataclass, and a PatchSandbox for LLM code. This ensures both F1 and F2 reuse the same secure base and avoids re‑implementing auth/scope/sandbox later.",
 "others_view": "Kimi and Gemma4 jump straight into API hardening and message‑bus work; they assume those pieces will be created as part of their respective phases without a dedicated foundation step.",
 "why_correct": "Starting with a common foundation reduces duplicated effort, guarantees consistent security controls across API and agents, and lets the CI/CD wrapper be a thin layer over existing battle‑tested phase engines, delivering value faster with lower risk."
 },
 {
 "point": "How the CI/CD (F2) wrapper should be implemented",
 "my_view": "Build a thin, headless FastAPI/CLI wrapper that directly invokes the existing phase engine (recon, scan, test, postex) after auth/scope checks. No need to re‑write the core logic; the wrapper focuses on API hardening, input validation, scope enforcement, and observability.",
 "others_view": "Both Kimi and Gemma4 propose new API endpoints that call into the brain or phase executors but also imply a more substantial rewrite of the orchestration layer (e.g., Kimi’s `orchestrator/api/[TARGET_DOMAIN]` with full mTLS/OIDC setup from scratch).",
 "why_correct": "Leveraging the existing, proven phase engine eliminates a major source of bugs, shortens the F2 timeline, and ensures that any later agent‑based replacement will have a stable baseline to compare against."
 },
 {
 "point": "Initial agent rollout strategy",
 "my_view": "Begin F1 with an OrchestratorAgent that delegates to the existing phase executors (i.e., reuses the current linear pipeline) and only then introduce specialist agents (Recon, Scan, Exploit, PostEx) one at a time. This validates the agent loop, messaging, and safety guards before adding complex, high‑risk behaviors.",
 "others_view": "Kimi starts with ReconAgent and ScanAgent (low‑risk) then adds ExploitAgent/PostExAgent (high‑risk); Gemma4 similarly begins with low‑risk agents after establishing the message bus and memory layer.",
 "why_correct": "By first wrapping the current pipeline in an agent abstraction we gain immediate observability and the ability to plug in HITL/checkpointing without altering the underlying tools. This reduces the risk of introducing bugs in low‑level tool handling while we prove the agent framework."
 }
 ],
 "integration_merges": [
 "From Kimi: defense‑in‑depth mindset, incremental agent rollout (low‑risk first), explicit observability and progress‑based fault isolation, and the idea of stealth controls / rate limiting.",
 "From Gemma4: hardened MessageBus with back‑pressure and dead‑letter queue, bounded async memory wrapper, least‑privilege AgentRole enums, GoalTree validation with deterministic fallback, HITL approval gates, state checkpointing, loop caps/heartbeat, and code sandbox (gVisor/Docker) for LLM‑generated Python.",
 "From Me (Human Architect): Phase 0 foundation (EventBus, API‑key/auth helper, AllowedScope dataclass, PatchSandbox), thin headless CI/CD API/CLI that wraps existing phase executors, webhook delivery with HMAC signing, CI templates (GitHub/GitLab), and the OrchestratorAgent that initially delegates to existing phase executors before adding specialists."
 ],
 "final_plan": {
 "phases": [
 {
 "phase": "Phase 0 Shared Foundation",
 "days": "1‑3",
 "objective": "Create reusable, secure primitives that both F1 and F2 will depend on.",
 "": [
 "EventBus (async, maxsize per subscriber, dead‑letter queue)",
 "API‑key/auth helper (env‑var loading, SHA256 hashing, role‑based scopes: admin/operator/viewer/agent)",
 "AllowedScope dataclass (loads YAML/JSON, provides allows_domain/IP/check)",
 "PatchSandbox (docker run --network=none --read-only --memory=256m --cpus=0.5 --timeout=30s)",
 "Basic logging/metrics scaffolding (structured JSON logs, Prometheus counters)"
 ],
 "integration_points": [
 "Existing CLI (`raphael_cli.py`) imports EventBus and emits events from all current commands",
 "Brain API imports auth helper and scope checker"
 ]
 },
 {
 "phase": "Phase 1 - F2: Hardened CI/CD Gateway",
 "days": "4‑10",
 "objective": "Expose a headless, API‑driven interface usable by any CI pipeline while enforcing all security controls.",
 "": [
 "FastAPI server with mTLS/OIDC/JWT middleware, HTTPSRedirect, TrustedHost",
 "Pydantic input models with strict regex validation for targets/IPs",
 "Scope enforcement dependency (uses AllowedScope from Phase 0)",
 "Endpoints: POST /v1/ci/engage, GET /v1/ci/engage/{id}, GET /v1/ci/report/{id}, GET /v1/ci/health",
 "Thin wrapper that calls existing phase engine functions (recon, scan, test, postex) after auth/scope",
 "Click‑based CLI (`raphael_ci.py`) for pipeline integration",
 "Dockerfile (python:3.11‑slim) exposing port 3999",
 "GitHub Actions & GitLab CI templates",
 "Webhook delivery service (HMAC‑signed, retry with back‑off)",
 "Observability: request logging, Prometheus histograms, error rates"
 ],
 "exit_criteria": [
 "A CI pipeline can block a deployment when critical findings are returned",
 "All API endpoints return 401/403 on missing/invalid auth or out‑of‑scope targets",
 "No command injection vectors (inputs strictly validated, sandboxed only for LLM code; not used here yet)"
 ]
 },
 {
 "phase": "Phase 2 F1: Agent Framework Core",
 "days": "11‑20",
 "objective": "Deploy the base agent infrastructure and an OrchestratorAgent that re‑uses the existing phase engine, proving the loop, safety guards, and observability.",
 "": [
 "MessageBus (async queue, maxsize, dead‑letter queue, Pydantic schema validation)",
 "Bounded Async Memory wrapper (batch writes, max_entities cap)",
 "Least‑privilege AgentRole enum (RECON, SCAN, TEST, POSTEX mapped to Linux users/Docker profiles)",
 "BaseAgent class (name, system_prompt, tools, max_iterations, heartbeat, should_terminate)",
 "OrchestratorAgent(BaseAgent): decompose → GoalTree, validate (scope, tool mapping, no circular deps), fallback to hard‑coded recon sweep, tick() with progress‑based replanning",
 "AgentMemory (episodic, semantic, procedural stores with bounded writes)",
 "GoalTree validation + deterministic fallback",
 "HITL approval gate (state‑machine pause for high‑risk actions, CLI prompt)",
 "State checkpointing (every 10 min) + heartbeat/livelock detection",
 "Loop caps & heartbeat in BaseAgent",
 "Code sandbox (gVisor/Docker, network=none, read‑only, resource limits) for LLM‑generated Python",
 "Observability: agent‑level logs, metrics (tasks processed, latency, errors), tracing IDs",
 "Unit & integration tests for message bus, memory, validation, sandbox"
 ],
 "integration_points": [
 "OrchestratorAgent delegates each leaf of GoalTree to existing phase executor functions (already imported from Phase 1)",
 "API from Phase 1 can now trigger an engagement via OrchestratorAgent instead of direct phase calls",
 "CLI gains a new subcommand `raphael agent run <target>` that starts the OrchestratorAgent"
 ],
 "exit_criteria": [
 "OrchestratorAgent successfully completes a full recon→scan→test→postex engagement on a test target",
 "All LLM‑generated code (if any) runs in the sandbox and is blocked on dangerous calls",
 "HITL gate correctly pauses and resumes on user input",
 "Checkpointing allows recovery after simulated crash",
 "No resource exhaustion observed under load testing"
 ]
 },
 {
 "phase": "Phase 3; F1: Specialist Agent Rollout (Incremental)",
 "days": "21‑45",
 "objective": "Add specialist agents one‑by‑one, beginning with low‑risk Recon and Scan agents, then Exploit and PostEx agents, each subject to the same safety controls.",
 "": [
 "ReconAgent: uses subdomain enumeration, port‑scanning, WAF detection, CVE lookup via Kali tools; publishes findings to MessageBus",
 "ScanAgent: runs dirb, nuclei, sqlmap, etc., respecting scope and rate limits; emits vulnerability findings",
 "ExploitAgent: only attempts exploits after HITL approval; runs Metasploit/impacket modules in sandbox; logs success/failure",
 "PostExAgent: establishes Sliver C2 sessions, performs lateral movement, credential dumping, exfiltration, all gated by HITL and scoped to allowed targets",
 "Each agent inherits BaseAgent, implements its own `tools` list, and reports progress via EventBus",
 "Dynamic replanning: OrchestratorAgent monitors agent heartbeats, detects stuck agents, and can reassign sub‑goals",
 "Enhanced observability: per‑agent metrics, dashboards, alerting on anomaly",
 "Documentation and runbooks for adding new agent types"
 ],
 "integration_points": [
 "Specialist agents publish findings to the same MessageBus used by OrchestratorAgent",
 "OrchestratorAgent subscribes to `finding.*` topics to update GoalTree progress",
 "CI/CD API can now optionally run the full multi‑agent flow (`POST /v1/ci/engage?use_agents=true`)",
 "Webhook receives final

---

## Gemma4 Round 2 (Refinement)

```json
{
  "agreement": {
    "strategic_value": "All three perspectives agree that F1 (Multi-Agent) and F2 (CI/CD) are essential to evolve Raphael from a linear tool into a professional-grade security platform. There is a consensus that the original proposal was too 'AI-optimistic' and lacked critical safety guardrails.",
    "risk_mitigation": "Universal agreement on the necessity of: 1) Strict scope enforcement to prevent out-of-scope targeting, 2) Input sanitization to prevent command injection into Kali tools, 3) Sandboxing for LLM-generated code, and 4) Bounded memory/resource limits to prevent OOM or system crashes.",
    "priority_shift": "All agree that the implementation must be incremental rather than a 'big bang' release, moving from low-risk infrastructure to high-risk autonomous agents."
  },
  "disagreement": {
    "sequencing": "Kimi and Gemma4 suggest a parallel or loosely coupled approach, whereas the Human Architect insists on a strict 'F2 First' sequence. The Architect's position is correct because F2 establishes the API, Auth, and Scope layers—the very 'perimeter' that F1 agents must operate within. Building the brain before the skull is a recipe for unmanaged risk.",
    "granularity_of_implementation": "Kimi provides high-level code snippets; Gemma4 provides a tabular requirement matrix; the Architect provides a file-system level implementation map. The Architect's approach is superior for actual engineering as it defines the exact architectural hooks (EventBus, PatchSandbox) required to make the system modular.",
    "failure_handling": "Kimi focuses on 'hallucinations,' Gemma4 on 'zombie agents,' and the Architect on 'livelock detection' and 'deterministic fallbacks.' The Architect's focus on a 'Hardcoded Safe Default' (recon_sweep) is the only viable way to ensure the system doesn't simply stop working when the LLM fails."
  },
  "integration_merges": {
    "from_kimi": "The 'Non-negotiable Modifications' list (HITL approvals, deterministic fallbacks, and compliance gating) will be integrated as P0 requirements in the Orchestration loop.",
    "from_gemma4": "The 'Least-Privilege Roles' mapping (e.g., RECON agent having no-write access to the filesystem) will be merged into the Agent Framework to ensure blast-radius containment.",
    "from_architect": "The 'Phase 0 Foundation' (EventBus, PatchSandbox, and SHA256 Auth) will serve as the mandatory prerequisite for all subsequent work."
  },
  "final_plan": {
    "phase_0_foundation_days_1_3": {
      "goal": "Establish the secure plumbing.",
      "key_deliverables": [
        "EventBus: Async pub/sub for agent communication with maxsize limits.",
        "Auth Layer: SHA256 hashed API keys and ScopeGuard for domain/IP validation.",
        "PatchSandbox: gVisor/Docker isolated environment for executing LLM-generated Python scripts with strict timeouts."
      ]
    },
    "phase_1_f2_ci_cd_gateway_days_4_12": {
      "goal": "Turn Raphael into a headless product.",
      "key_deliverables": [
        "FastAPI Wrapper: /engage and /scan endpoints with mTLS/OIDC support.",
        "CI CLI: 'raphael-ci' tool for pipeline integration (SARIF/JUnit output).",
        "Pipeline Templates: GitHub Actions and GitLab CI YAMLs.",
        "Webhook System: Signed delivery of findings to external endpoints."
      ]
    },
    "phase_2_f1_agent_framework_days_13_30": {
      "goal": "Implement the cognitive architecture.",
      "key_deliverables": [
        "BaseAgent Class: Lifecycle management (run -> result) with max_iterations and heartbeat.",
        "OrchestratorAgent: GoalTree generation with a deterministic validator and 'Safe Default' fallback.",
        "Bounded Memory: Neo4j/pgvector wrapper with batch writes and entity caps to prevent OOM.",
        "Role-Based Access: Mapping agents to specific Docker profiles (e.g., ScanAgent cannot execute shells)."
      ]
    },
    "phase_3_agent_rollout_days_31_55": {
      "goal": "Incremental intelligence deployment.",
      "key_deliverables": [
        "Low-Risk Rollout: Deploy ReconAgent and ScanAgent; validate via CI/CD pipeline.",
        "High-Risk Rollout: Deploy ExploitAgent and PostExAgent with mandatory HITL (Human-In-The-Loop) approval gates.",
        "Stability Tuning: Implement livelock detection and state checkpointing for crash recovery."
      ]
    }
  }
}
```

---

## Me Round 2 (Refinement)

## My Refined Response (After Seeing Kimi + Gemma4)

### Agreement
All three of us converge on:
1. **YES, but F2 first** — CI/CD is the lower-risk, higher-immediacy value. Build it as a wrapper around existing phase engine.
2. **Neo4j/pgvector are premature** — Start with GrowthDB/SQLite. Add graph + vector stores only when queries prove they're needed.
3. **Sandbox is non-negotiable** — Any LLM-generated code must run isolated. Docker --rm or gVisor.
4. **GoalTree validation is critical** — LLM halluncination on goal decomposition will kill engagement reliability. Must have deterministic fallback.

### Disagreements Resolved
- **MessageBus complexity**: Kimi wants full pub/sub with back-pressure. Gemma4 wants direct calls. I split the difference: `asyncio.Queue` pairs in v1, upgrade to proper bus in v2. Both models accepted this compromise.
- **Scope file enforcement**: Gemma4 correctly notes this is P0 for F2 (CI/CD could scan unauthorized targets). I agree — moved to Phase 1.
- **Agent loop iteration caps**: Kimi called this out as missing from my original plan. Correct. Added `max_iterations=50` to BaseAgent.

### Final Merged Plan
Take my Phase 0-4 structure but:
- Add scope file enforcement to Phase 1 (gemma4's point)
- Make memory writes explicitly capped and async (kimi's point)
- Keep ExploitAgent sandboxed from day 1 (all three agree)
- Skip Neo4j until v2 (gemma4 + me agree; kimi conceded)

---

## Final Synthesis (Kimi)

{
 "verdict": "YES, but only F2 first",
 "unified_plan": {
 "summary": "The plan delivers immediate DevSecOps value by hardening Raphael’s existing phase engine into a secure, API‑driven CI/CD gateway (F2) before introducing autonomous agents (F1). A shared security foundation (EventBus, auth/scope helpers, sandboxed execution, logging/metrics) is built first so that both F2 and later F1 components reuse the same controls. After the gateway is proven, a lightweight agent framework is added that wraps the current linear pipeline, enabling observability, checkpointing, and human‑in‑the‑loop gates. Agents are then rolled out incrementally starting with low‑risk recon/scan specialists and progressing to high‑risk exploit/post‑ex specialists with mandatory approvals - ensuring safety, bounded resource use, and clear rollback paths.",
 "phases": [
 {
 "phase": 1,
 "name": "Phase 0 Shared Security Foundation",
 "items": [
 {"file": "raphael/eventbus.py", "action": "create", "detail": "Async pub/sub with per‑subscriber maxsize, dead‑letter queue, and basic metrics.", "priority": "P0", "loc_estimate": 80},
 {"file": "raphael/auth.py", "action": "create", "detail": "Helper for loading API keys (SHA256 hashed), JWT/OIDC middleware stub, and role‑based scopes (admin/operator/viewer/agent).", "priority": "P0", "loc_estimate": 60},
 {"file": "raphael/scope.py", "action": "create", "detail": "AllowedScope dataclass loading YAML/JSON, providing allows_domain/IP/check functions.", "priority": "P0", "loc_estimate": 40},
 {"file": "raphael/sandbox.py", "action": "create", "detail": "PatchSandbox wrapper using docker run --network=none --read-only --memory=256m --cpus=0.5 --timeout=30s (or gVisor).", "priority": "P0", "loc_estimate": 50},
 {"file": "raphael/logging.py", "action": "create", "detail": "Structured JSON logger and Prometheus counters (events processed, errors, latency).", "priority": "P0", "loc_estimate": 30},
 {"file": "raphael_cli.py", "action": "action":"Import EventBus, after each CLI entrypoint, "action": "modify", "detail": "Import EventBus and emit events for recon, scan, test, postex commands.", "priority": "P0", "loc_estimate": 20}
 ],
 "estimated_days": 3,
 "gate": "Foundation primitives are unit‑tested, imported without errors by the existing CLI and Brain API, and basic logging/metrics are observable."
 },
 {
 "phase": 2,
 "name": "Phase 1 F2: Hardened CI/CD Gateway",
 "items": [
 {"file": "gateway/fastapi_app.py", "action": "create", "detail": "FastAPI server with mTLS/OIDC/JWT middleware, HTTPSRedirect, TrustedHost, and scope enforcement dependency (uses AllowedScope).", "priority": "P0", "loc_estimate": 120},
 {"file": "gateway/endpoints.py", "action": "create", "detail": "POST /v1/ci/engage (starts a phase run), GET /v1/ci/engage/{id} (status), GET /v1/ci/engage/{id}/results (SARIF/JUnit). Input models use strict regex validation for targets/IPs.", "priority": "P0", "loc_estimate": 100},
 {"file": "gateway/ci_cli.py", "action": "create", "detail": "‘raphael-ci’ CLI tool for pipeline integration; wraps /engage, outputs SARIF/JUnit, handles retries and back‑off.", "priority": "P0", "loc_estimate": 60},
 {"file": "gateway/webhook.py", "action": "create", "detail": "Signed webhook delivery (HMAC‑SHA256) of findings to external endpoints; includes retry queue and dead‑letter handling.", "priority": "P0", "loc_estimate": 50},
 {"file": "ci/templates/", "action": "create", "detail": "GitHub Actions and GitLab CI YAMLs that invoke raphael-ci with appropriate secrets and scope files.", "priority": "P0", "loc_estimate": 30},
 {"file": "raphael/scope_enforcement.py", "action": "create", "detail": "Middleware that checks incoming target against AllowedScope; rejects out‑of‑scope requests with 403.", "priority": "P0", "loc_estimate": 40},
 {"file": "gateway/Dockerfile", "action": "create", "detail": "Production‑ready image with non‑root user, read‑only FS, and healthcheck endpoint.", "priority": "P0", "loc_estimate": 20}
 ],
 "estimated_days": 7,
 "gate": "Gateway passes automated security scan (nuclei, bandit), scope enforcement blocks unauthorized targets, and CI templates succeed in a staging pipeline."
 },
 {
 "phase": 3,
 "name": "Phase 2; F1: Agent Framework & Orchestrator",
 "items": [
 {"file": "agents/base_agent.py", "action": "create", "detail": "BaseAgent class with lifecycle (setup -> run -> teardown), max_iterations=50, heartbeat, and checkpoint hooks.", "priority": "P0", "loc_estimate": 80},
 {"file": "agents/orchestrator_agent.py", "action": "create", "detail": "OrchestratorAgent that builds a GoalTree from the goal, runs a deterministic validator, and falls back to a hardcoded safe default (recon_sweep) on LLM failure.", "priority": "P0", "loc_estimate": 100},
 {"file": "agents/memory.py", "action": "create", "detail": "Bounded async wrapper around GrowthDB/SQLite with max entities, batch writes, and automatic eviction to prevent OOM.", "priority": "P0", "loc_estimate": 70},
 {"file": "agents/role.py", "action": "create", "detail": "AgentRole enum (RECON, SCAN, EXPLOIT, POSTEX) mapped to Docker profiles (e.g., EXPLOIT gets no filesystem write, POSTEX gets limited shell).", "priority": "P0", "loc_estimate": 40},
 {"file": "agents/sandbox_executor.py", "action": "create", "detail": "Executor that runs LLM‑generated Python inside PatchSandbox; validates output before returning.", "priority": "P0", "loc_estimate": 50},
 {"file": "agents/event_handlers.py", "action": "create", "detail": "Agents publish/subscribe via EventBus (low‑risk events only in v1); includes dead‑letter handling.", "priority": "P0", "loc_estimate": 60},
 {"file": "agents/hitl_gate.py", "action": "create", "detail": "Human‑in‑the‑loop approval gate that pauses the agent loop for high‑risk actions and requires manual confirmation via API or CLI.", "priority": "P0", "loc_estimate": 40}
 ],
 "estimated_days": 18,
 "gate": "Framework passes unit and integration tests; OrchestratorAgent can successfully run the existing phase engine (recon→scan→test→postex) with HITL stub and sandboxed code execution."
 },
 {
 "phase": 4,
 "name": "Phase 3; Incremental Agent Rollout",
 "items": [
 {"file": "agents/recon_agent.py", "action": "create", "detail": "ReconAgent that uses existing recon module; limited to read‑only network scans.", "priority": "P1", "loc_estimate": 50},
 {"file": "agents/scan_agent.py", "action": "create", "detail": "ScanAgent that wraps nuclei/dirb; no file‑system writes beyond scoped output dir.", "priority": "P1", "loc_estimate": 50},
 {"file": "agents/exploit_agent.py", "action": "create", "detail": "ExploitAgent that runs Metasploit/impacket inside PatchSandbox; requires HITL approval before execution.", "priority": "P2", "loc_estimate": 80},
 {"file": "agents/postex_agent.py", "action": "create", "detail": "PostExAgent for lateral movement and data collection; runs in sandbox with no‑network‑outbound unless explicitly allowed; HITL gate mandatory.", "priority": "P2", "loc_estimate": 80},
 {"file": "agents/monitoring.py", "action": "create", "detail": "Livelock detection (heartbeat timeout > 2m), state checkpointing to disk, and automatic restart on failure.", "priority": "P1", "loc_estimate": 60},
 {"file": "docs/rollout.md", "action": "create", "detail": "Run‑book describing low‑risk then high‑risk agent deployment, rollback procedures, and metrics to watch.", "priority": "P1", "loc_estimate": 30}
 ],
 "estimated_days": 27,
 "gate": "Low‑risk agents (Recon, Scan) demonstrate stable operation in CI/CD pipeline; high‑risk agents only activate after HITL approval and show no privilege escalation or container escape in security testing."
 }
 ],
 "total_estimated_days": 55,
 "dependencies": {
 "raphael/eventbus.py": ["raphael/logging.py"],
 "gateway/fastapi_app.py": ["raphael/auth.py", "raphael/scope.py"],
 "gateway/endpoints.py": ["gateway/fastapi_app.py", "raphael/scope_enforcement.py"],
 "agents/base_agent.py": ["raphael/eventbus.py", "raphael/logging.py"],
 "agents/orchestrator_agent.py": ["agents/base_agent.py", "agents/memory.py", "agents/hitl_gate.py"],
 "agents/memory.py": ["raphael/logging.py"],
 "agents/sandbox_executor.py": ["raphael/sandbox.py"],
 "agents/recon_agent.py": ["agents/base_agent.py"],
 "agents/scan_agent.py": ["agents/base_agent.py"],
 "agents/exploit_agent.py": ["agents/base_agent.py", "agents/sandbox_executor.py", "agents/hitl_gate.py"],
 "agents/postex_agent.py": ["agents/base_agent.py", "agents/sandbox_executor.py", "agents/hitl_gate.py"]
 }
 },
 "key_tradeoffs": [
 "SQLite/GrowthDB instead of Neo4j/pgvector - simpler, bounded, and sufficient until complex relationship queries prove necessary.",
 " existing phase engine via thin wrapper rather than rewriting core logic; reduces bug surface and accelerates F2 delivery.",
 "Start with lightweight EventBus (direct async pub/sub) and plan to upgrade to a full‑featured bus with back‑pressure in v2 avoids over‑engineering early.",
 "Delay Neo4j/pgvector and advanced graph‑based reasoning until agent rollout shows a clear need for relationship traversal."
 ],
 "what_to_skip": [
 "Full Neo4j/pgvector integration in the initial memory layer.",
 "Building a heavyweight message broker (e.g., RabbitMQ/Kafka) for v1; use the in‑process EventBus with dead‑letter queue.",
 "Rewriting the reconnaissance, scanning, exploitation, and post‑exploitation modules from scratch; reuse the battle‑tested existing commands.",
 "Attempting to allow LLM‑generated shell scripts to run outside the PatchSandbox; keep all code execution strictly sandboxed."
 ],
 "integration_wiring": "The existing raphael_cli.py is updated to import the shared EventBus and emit a structured event after each phase command (recon, scan, test, postex). The Brain API (brain/[TARGET_DOMAIN]/…) uses the auth helper and scope checker to validate incoming requests before delegating to the phase engine. The new CI/CD gateway (gateway/fastapi_app.py) imports the same auth/scope helpers, enforces scope per request, and then either calls the phase engine directly (via import) or spawns the CLI as a subprocess, returning structured results (SARIF/JUnit) and triggering signed webhooks. Agents instantiate BaseAgent subclasses; they publish lifecycle events (agent_start, agent_action, agent_complete) to the EventBus, which the gateway can subscribe to for real‑time progress streaming. The OrchestratorAgent’s GoalTree validator and deterministic fallback are pure‑Python and do not depend on external services, ensuring the system can continue operating even if the LLM hallucinates or is unavailable. All agent‑side code execution (including LLM‑generated Python) goes through PatchSandbox, guaranteeing that any malicious or erroneous code is confined to a restricted container with no network, limited CPU/memory, and a read‑only filesystem. Monitoring, heartbeat, and checkpointing agents write state to the bounded GrowthDB, enabling crash recovery and livelock detection without unbounded resource growth."
 }
}
