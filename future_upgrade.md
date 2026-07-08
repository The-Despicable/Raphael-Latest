# Raphael 2.0 — Future Upgrades

> Two architectural leaps that close the gap with commercial/open-source competitors: multi-agent AI and CI/CD integration.

---

## F1 — Multi-Agent AI Architecture

**Problem:** Raphael has a single REPL + a deterministic 8-phase pipeline. The LLM is used for strategy (analyzing findings, suggesting next-phase focus), but the actual tool execution is hardcoded Python. PentAGI shows what's possible with specialized agents collaborating — Researcher, Developer, Executor, each with dedicated tools and memory.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR AGENT                        │
│  Receives target + objective, decomposes into sub-tasks,        │
│  delegates to specialist agents, synthesizes results,           │
│  decides when engagement is complete                            │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│  RECON AGENT │  SCAN AGENT  │ EXPLOIT AGENT│ POST-EX AGENT     │
│  (researcher)│  (analyst)   │ (developer)  │ (operator)        │
├──────────────┴──────────────┴──────────────┴───────────────────┤
│                    SHARED MEMORY LAYER                           │
│  GrowthDB (targets/findings) + Neo4j (knowledge graph)          │
│  + pgvector (semantic embeddings for cross-session recall)      │
├─────────────────────────────────────────────────────────────────┤
│                    TOOL EXECUTION LAYER                          │
│  Kali Tools API (899 tools) + Pure Python scanners + Sliver C2  │
└─────────────────────────────────────────────────────────────────┘
```

### F1a — Agent Definitions

Each agent is its own async loop with a specialized system prompt and toolset:

| Agent | System Prompt Persona | Tools | Memory |
|-------|----------------------|-------|--------|
| **Orchestrator** | "You are a red team lead planning an engagement. Decompose the objective into subtasks, assign them to specialists, and synthesize their output. You do not run tools yourself." | Engagement state, agent routing, goal tree | Full engagement history |
| **Recon Agent** | "You are an OSINT analyst. Your job is to discover everything about the target before any tool touches it." | web_search, fetch_url, DNS, whatweb, subfinder, nmap -sV, Shodan (if keyed) | GrowthDB targets |
| **Scan Agent** | "You are a vulnerability analyst. Run the appropriate scanners based on recon results. Prioritize by likelihood of exploit." | nuclei, nmap scripts, nikto, gobuster, FFuF, SQLi/XSS probes | GrowthDB findings |
| **Exploit Agent** | "You are an exploit developer. Chain vulnerabilities to achieve code execution or credential access. Write custom payloads when existing tools don't cover the attack path." | sqlmap, Metasploit, hydra, custom Python exploit generation, payloads DB | GrowthDB techniques |
| **Post-Ex Agent** | "You are an operator managing compromised hosts. Establish persistence, move laterally, escalate privileges, exfiltrate data." | Sliver C2, impacket, bloodhound, certipy, socat, exfil pipeline | C2 session store |

### F1b — Implementation Plan

**Phase 1 — Agent Framework** (1 week)

```
orchestrator/agents/
├── __init__.py
├── base.py              # BaseAgent class with shared lifecycle
├── orchestrator.py      # OrchestratorAgent — goal decomposition, routing
├── recon.py             # ReconAgent — OSINT, passive enumeration
├── scan.py              # ScanAgent — vulnerability detection
├── exploit.py           # ExploitAgent — exploitation + payload generation
├── postex.py            # PostExAgent — persistence, lateral, exfil
├── memory.py            # AgentMemory — shared context store per engagement
├── bus.py               # MessageBus — async event passing between agents
└── supervisor.py        # AgentSupervisor — health monitoring, dead agent recovery
```

**BaseAgent lifecycle:**

```python
class BaseAgent:
    """All agents follow this lifecycle."""

    name: str                     # "recon", "scan", etc.
    system_prompt: str            # Specialized persona
    tools: list[ToolDef]          # What this agent can call
    max_consecutive_failures: int = 3

    async def run(self, task: Task, context: Context) -> Result:
        """Receive a task from orchestrator, execute it, return findings."""
        while task.status == "running":
            # 1. Think: LLM call with current context + tools
            thought = await self.think(context)

            # 2. Act: execute tool calls, store findings
            for action in thought.actions:
                result = await self.execute(action)
                context.add_finding(result)

            # 3. Report: send progress back to orchestrator
            await self.bus.emit("agent_progress", {
                "agent": self.name,
                "task_id": task.id,
                "findings": result,
            })

            # 4. Check termination (task complete, stuck, or out of scope)
            if self.should_terminate(context):
                break
```

**Orchestrator goal decomposition:**

```python
class OrchestratorAgent:
    """
    Turns "compromise 10.0.1.0/24" into a dynamic plan.

    Example decomposition:
        root: "compromise 10.0.1.0/24"
        ├── recon(10.0.1.0/24) → discovers live hosts: 10.0.1.5, 10.0.1.10
        ├── scan(10.0.1.5)     → finds: port 80 (Apache 2.4.49), port 22 (OpenSSH 8.0)
        ├── scan(10.0.1.10)    → finds: port 443 (nginx 1.20), AD on port 389
        ├── exploit(10.0.1.5)  → CVE-2021-41773 (path traversal on Apache 2.4.49)
        │   └── postex(10.0.1.5) → drop agent, dump /etc/shadow
        ├── exploit(10.0.1.10) → kerberoasting via GetUserSPNs
        │   └── postex(10.0.1.10) → bloodhound, certipy ESC1
        └── lateral(10.0.1.5 → 10.0.1.10) → use cracked SSH key
            └── escalate → domain admin via DC sync
    """

    async def decompose(self, objective: str, target: str) -> GoalTree:
        """Call LLM to generate goal tree, then instantiate sub-agents."""
        tree = await self.llm.generate_goal_tree(objective, target)
        for goal in tree.leaves():
            agent = self.agent_for(goal.type)  # recon → ReconAgent
            task = self.spawn_task(goal, agent)
            self.active_tasks.append(task)
        return tree

    async def tick(self):
        """Main loop: check task progress, handle failures, replan."""
        for task in self.active_tasks:
            if task.is_stuck(duration=300):  # 5 min without progress
                alt = await self.replan(task.goal)
                self.spawn_task(alt, self.agent_for(alt.type))
                task.cancel()
            if task.is_done:
                findings = task.collect_findings()
                new_goals = await self.synthesize(findings)
                for g in new_goals:
                    self.spawn_task(g, self.agent_for(g.type))
```

**Phase 2 — Knowledge Graph Integration** (3-4 days)

Replace GrowthDB's flat SQLite with a proper knowledge graph for agent memory:

```python
# orchestrator/agents/memory.py
class AgentKnowledge:
    """
    Shared memory across agents. Three layers:
    1. Episodic — per-engagement event log (SQLite)
    2. Semantic — embedding search for cross-session pattern matching (pgvector)
    3. Relational — entity graph: Target --has--> Vuln --exploited_by--> Technique (Neo4j)
    """

    async def store_finding(self, finding: Finding, agent: str):
        """All agents write findings here. Other agents can query them."""
        # 1. Store raw finding
        await self.episodic.store(finding)

        # 2. Generate embedding for similarity search
        embedding = await self.embed(finding.description)
        await self.semantic.store(finding.id, embedding)

        # 3. Update knowledge graph
        await self.graph.merge("Target", {"ip": finding.host})
        await self.graph.merge("Vulnerability", {"cve": finding.cve, "type": finding.type})
        await self.graph.relate(
            "Target", {"ip": finding.host},
            "HAS_VULNERABILITY",
            "Vulnerability", {"cve": finding.cve},
            properties={"found_by": agent, "severity": finding.severity}
        )

    async def query_similar(self, target: str) -> list[Finding]:
        """Retrieve findings from past engagements on similar targets."""
        # Hybrid: vector similarity + graph traversal
        embedding = await self.embed(target)
        vector_results = await self.semantic.search(embedding, k=10)
        graph_results = await self.graph.query(
            "MATCH (t:Target {ip: $ip})-[r:HAS_VULNERABILITY]->(v) RETURN v",
            {"ip": target}
        )
        return self.merge_results(vector_results, graph_results)
```

**Phase 3 — Wire into REPL** (2-3 days)

```python
# In raphael_cli.py — new command
@cli.command("/agent-engage")
async def agent_engage(target: str):
    """Start a multi-agent engagement against target."""
    orch = OrchestratorAgent()
    tree = await orch.decompose("compromise", target)

    # Live dashboard showing agent activity
    with Live(renderable=make_agent_dashboard(tree), refresh_per_second=2):
        while not tree.is_complete:
            await orch.tick()
            await asyncio.sleep(0.5)
```

**Agent dashboard in the terminal:**

```
┌──────────────────────────────────────────────────────────────────┐
│  Multi-Agent Engagement — 10.0.1.0/24          Elapsed: 12m 34s  │
├──────────────────────────────────────────────────────────────────┤
│  🔵 Recon    ████████████████████████████████░░░  8 hosts found  │
│  🟡 Scan     ████████████████░░░░░░░░░░░░░░░░░░░  ▌▌ 2/8 done    │
│  ⚪ Exploit   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  pending        │
│  ⚪ PostEx    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  pending        │
├──────────────────────────────────────────────────────────────────┤
│  Latest findings:                                                 │
│  │ Recon   │ 10.0.1.5    │ Ports: 22, 80, 443  │ Apache 2.4.49 │
│  │ Recon   │ 10.0.1.10   │ Ports: 389, 443, 88 │ Domain Ctrl   │
│  │ Scan    │ 10.0.1.5    │ CVE-2021-41773      │ Path traversal │
│  │ Scan    │ 10.0.1.10   │ MS-DS PC             │ Kerberoastable│
```

### What This Unlocks

| Capability | Current Raphael | With F1 |
|-----------|----------------|---------|
| Parallel recon & scan | Sequential phases | ReconAgent discovers hosts while ScanAgent begins on confirmed live ones |
| Dynamic goal replanning | Fixed phase order | Orchestrator can skip exploit on host A if it's a dead end, double down on host B |
| Cross-session learning | GrowthDB stores flat findings | AgentKnowledge retrieves "that technique worked on a similar target 3 engagements ago" |
| Custom exploit generation | Hardcoded sqlmap | ExploitAgent can write Python payloads on-the-fly |
| Fault isolation | Phase fails → whole chain stops | Orchestrator detects stuck agent, spawns alternative approach, kills dead subtasks |

---

## F2 — CI/CD Integration

**Problem:** Raphael is an interactive REPL. There's no way to trigger a pentest from a CI/CD pipeline, and no way to consume results programmatically. NodeZero and Pentera both expose REST APIs + CLIs that allow `curl https://pentera/api/task/start` or `h3 pentest start --target 10.0.1.0/24` from any pipeline step.

### F2a — Raphael REST API (Headless Mode)

Create a FastAPI-based API server that can be started independently of the REPL:

```yaml
# docker-compose.yml — new service
services:
  raphael-api:
    build: ./orchestrator
    container_name: raphael-api
    ports:
      - "3999:3999"
    environment:
      - RAPHAEL_MODE=headless    # ← no REPL, API-only
      - API_KEY_FILE=/run/secrets/api_key
    depends_on: [kali-tools, tor-proxy, neo4j]
```

**API Endpoints:**

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| `POST` | `/v1/ci/engage` | Start new engagement | Bearer token |
| `GET` | `/v1/ci/engage/{id}` | Get engagement status + results | Bearer token |
| `POST` | `/v1/ci/engage/{id}/cancel` | Stop running engagement | Bearer token |
| `GET` | `/v1/ci/findings` | List all findings across engagements | Bearer token |
| `GET` | `/v1/ci/health` | Health check for CI gating | None (probe) |
| `GET` | `/v1/ci/report/{id}` | Export structured report (JSON) | Bearer token |

**CI-focused engage endpoint:**

```python
# orchestrator/api/ci.py
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional

app = FastAPI(title="Raphael CI API", version="1.0")

class CIEngageRequest(BaseModel):
    target: str                             # "10.0.1.0/24" or "app.targetcorp.com"
    phases: Optional[list[str]] = None      # default: all phases
    depth: str = "standard"                 # "quick" | "standard" | "deep"
    scope: Optional[dict] = None            # scope enforcement
    webhook_url: Optional[str] = None       # POST results here when done
    priority: int = 50                      # 0-100, higher = first

class CIEngageResponse(BaseModel):
    engagement_id: str
    status: str                             # "queued" | "running"
    position: int                           # queue position
    estimated_duration: str
    webhook: Optional[str] = None

@app.post("/v1/ci/engage", response_model=CIEngageResponse)
async def ci_engage(
    req: CIEngageRequest,
    authorization: str = Header(...),
    api_keys: dict = Depends(load_api_keys),
):
    """Start an engagement from CI/CD. Returns immediately with engagement_id."""
    key = authorization.removeprefix("Bearer ")
    if key not in api_keys:
        raise HTTPException(401, "Invalid API key")

    eid = await orchestrator.enqueue(
        target=req.target,
        phases=req.phases or DEFAULT_PHASES,
        priority=req.priority,
        depth=req.depth,
    )

    # Optionally register webhook for async result delivery
    if req.webhook_url:
        await webhook_register(eid, req.webhook_url)

    return CIEngageResponse(
        engagement_id=eid,
        status="queued",
        position=orchestrator.queue_position(eid),
        estimated_duration=estimate_duration(req.depth, req.target),
    )

@app.get("/v1/ci/engage/{eid}", response_model=CIEngageResponse)
async def ci_status(eid: str, authorization: str = Header(...)):
    """Poll engagement status from CI pipeline."""
    eng = orchestrator.get(eid)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return CIEngageResponse(
        engagement_id=eid,
        status=eng.status,
        position=orchestrator.queue_position(eid) if eng.status == "queued" else 0,
        estimated_duration=eng.duration,
    )

@app.get("/v1/ci/report/{eid}")
async def ci_report(eid: str, authorization: str = Header(...)):
    """Return structured findings as JSON for CI consumption."""
    eng = orchestrator.get(eid)
    if not eng or eng.status != "done":
        raise HTTPException(404, "Engagement not found or not complete")
    return {
        "engagement_id": eid,
        "target": eng.target,
        "duration": eng.duration,
        "total_findings": len(eng.findings),
        "critical": [f for f in eng.findings if f.severity == "critical"],
        "high": [f for f in eng.findings if f.severity == "high"],
        "medium": [f for f in eng.findings if f.severity == "medium"],
        "summary": eng.summary,
        "compliance_mapped": map_to_frameworks(eng.findings),  # PCI, SOC2, HIPAA
    }
```

### F2b — `raphael-ci` CLI Tool

A standalone CLI similar to `h3-cli` for NodeZero:

```bash
# Install
pip install raphael-cli

# Authenticate
raphael-ci auth login --api-key sk-xxxx

# Run a pentest (blocking — waits for results)
raphael-ci engage run 10.0.1.0/24 --depth standard

# Run in CI mode (non-blocking, poll later)
raphael-ci engage start app.targetcorp.com --webhook https://ci/api/webhook

# Check status
raphael-ci engage status abc123

# Export findings
raphael-ci report abc123 --format json  > findings.json
raphael-ci report abc123 --format sarif  > findings.sarif   # SARIF for GitHub
raphael-ci report abc123 --format junit > findings.xml      # JUnit for Jenkins

# List recent engagements
raphael-ci engage list --limit 10

# Health check
raphael-ci health
```

```python
# cli/raphael_ci.py
#!/usr/bin/env python3
"""
Raphael CI CLI — trigger and monitor pentests from CI/CD pipelines.
Usage:
    raphael-ci engage run <target> [--depth quick|standard|deep] [--timeout 3600]
    raphael-ci engage start <target> [--webhook URL]
    raphael-ci engage status <id>
    raphael-ci report <id> [--format json|sarif|junit]
    raphael-ci health
"""
import click, httpx, json, time, os, sys
from typing import Optional

API_BASE = os.getenv("RAPHAEL_CI_URL", "http://localhost:3999")

@click.group()
def cli():
    pass

@cli.command()
@click.argument("target")
@click.option("--depth", default="standard")
@click.option("--timeout", default=3600, help="Max wait seconds (blocking)")
@click.option("--poll-interval", default=15, help="Seconds between status checks")
def run(target, depth, timeout, poll_interval):
    """Run engagement and block until complete (for CI pipelines)."""
    api_key = _require_api_key()

    # Start engagement
    resp = httpx.post(
        f"{API_BASE}/v1/ci/engage",
        json={"target": target, "depth": depth},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp.raise_for_status()
    eid = resp.json()["engagement_id"]
    click.echo(f"Engagement {eid} started — polling...")

    # Poll until done or timeout
    start = time.time()
    while time.time() - start < timeout:
        resp = httpx.get(
            f"{API_BASE}/v1/ci/engage/{eid}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        status = resp.json()["status"]
        if status == "done":
            click.echo(f"✅ Engagement {eid} complete")
            break
        elif status == "failed":
            click.echo(f"❌ Engagement {eid} failed", err=True)
            sys.exit(1)
        click.echo(f"  Status: {status} — checking again in {poll_interval}s...")
        time.sleep(poll_interval)
    else:
        click.echo(f"⏱️  Timeout waiting for {eid}", err=True)
        sys.exit(1)

    # Print findings summary
    report = httpx.get(
        f"{API_BASE}/v1/ci/report/{eid}",
        headers={"Authorization": f"Bearer {api_key}"},
    ).json()
    _print_summary(report)

    # Exit with error code if critical findings exist
    if len(report.get("critical", [])) > 0:
        click.echo("❌ Critical findings detected — failing CI step", err=True)
        sys.exit(1)

@cli.command()
@click.argument("target")
@click.option("--webhook")
@click.option("--depth", default="standard")
def start(target, webhook, depth):
    """Start engagement, return immediately (non-blocking)."""
    api_key = _require_api_key()
    resp = httpx.post(
        f"{API_BASE}/v1/ci/engage",
        json={"target": target, "depth": depth, "webhook_url": webhook},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp.raise_for_status()
    data = resp.json()
    click.echo(json.dumps(data, indent=2))

@cli.command()
@click.argument("eid")
def status(eid):
    """Poll engagement status."""
    api_key = _require_api_key()
    resp = httpx.get(
        f"{API_BASE}/v1/ci/engage/{eid}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp.raise_for_status()
    click.echo(json.dumps(resp.json(), indent=2))

@cli.command()
@click.argument("eid")
@click.option("--format", "-f", default="json")
def report(eid, format):
    """Export findings report."""
    api_key = _require_api_key()
    resp = httpx.get(
        f"{API_BASE}/v1/ci/report/{eid}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp.raise_for_status()
    data = resp.json()

    if format == "json":
        click.echo(json.dumps(data, indent=2))
    elif format == "sarif":
        click.echo(json.dumps(_to_sarif(data), indent=2))
    elif format == "junit":
        click.echo(_to_junit_xml(data))
```

### F2c — CI Pipeline Integrations

**GitHub Actions:**

```yaml
# .github/workflows/raphael-pentest.yml
name: Raphael Security Scan
on:
  push:
    branches: [main, staging]
  pull_request:
    branches: [main]

jobs:
  pentest:
    runs-on: ubuntu-latest
    services:
      raphael:
        image: raphael/api:latest
        ports: ["3999:3999"]
        env:
          RAPHAEL_MODE: headless
          API_KEY: ${{ secrets.RAPHAEL_API_KEY }}
    steps:
      - uses: actions/checkout@v4

      # Deploy the app to a staging environment
      - name: Deploy to staging
        run: |
          docker compose -f deploy/docker-compose.yml up -d
          # Wait for deployment health

      - name: Run Raphael security scan
        run: |
          pip install raphael-cli
          raphael-ci engage run ${{ vars.STAGING_URL }} \
            --depth standard \
            --timeout 600

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

**GitLab CI:**

```yaml
# .gitlab-ci.yml
raphael-security:
  image: python:3.11
  services:
    - name: raphael/api:latest
      alias: raphael
  variables:
    RAPHAEL_CI_URL: "http://raphael:3999"
  script:
    - pip install raphael-cli
    - raphael-ci engage run ${CI_ENVIRONMENT_URL} --depth quick --timeout 300
    - raphael-ci report ${ENGAGEMENT_ID} --format junit > raphael-results.xml
  artifacts:
    reports:
      junit: raphael-results.xml
    when: always
  only:
    - main
    - staging
```

**Jenkins Pipeline:**

```groovy
// Jenkinsfile
pipeline {
    agent any
    environment {
        RAPHAEL_CI_URL = 'http://raphael-api:3999'
    }
    stages {
        stage('Deploy to Staging') {
            steps {
                sh 'docker compose -f deploy/docker-compose.yml up -d'
            }
        }
        stage('Security Scan') {
            steps {
                sh '''
                    pip install raphael-cli
                    raphael-ci engage run ${STAGING_URL} --depth standard --timeout 600
                '''
            }
            post {
                always {
                    sh 'raphael-ci report ${ENGAGEMENT_ID} --format junit > raphael-results.xml'
                    junit 'raphael-results.xml'
                }
                failure {
                    // If critical findings, block deployment
                    sh 'raphael-ci report ${ENGAGEMENT_ID} --format json | jq "."
                    // Send Slack alert
                }
            }
        }
    }
}
```

**Webhook payload (async result delivery):**

```json
POST /ci/webhook HTTP/1.1
Content-Type: application/json
X-Raphael-Signature: sha256=<hmac_signature>

{
  "event": "engagement.complete",
  "engagement_id": "abc123",
  "target": "staging.app.corp",
  "status": "done",
  "duration_seconds": 487,
  "summary": "Found 12 vulnerabilities (3 critical, 5 high, 4 medium)",
  "findings_url": "http://raphael-api:3999/v1/ci/report/abc123",
  "fail_ci": true,
  "critical_findings": [
    {
      "type": "sql_injection",
      "endpoint": "/api/login",
      "cve": null,
      "severity": "critical",
      "evidence": "Extracted user table: admin@corp.com:$2b$12$..."
    }
  ]
}
```

### F2d — Scope File for CI

CI pipelines need strict scope enforcement — no accidental scanning of unauthorized targets:

```yaml
# raphael-scope.yml — checked into repo
version: 1.0
engagement:
  target: "staging.app.corp"
  allowed_domains:
    - "staging.app.corp"
    - "*.staging.app.corp"
  allowed_ips:
    - "10.0.0.0/8"
  excluded:
    - "admin.staging.app.corp"  # Out of scope per policy
  depth: "standard"
  rate_limit: 2.0               # Requests per second
  business_hours_only: true     # Only scan 9-5
  notify:
    on_complete: slack://#security-alerts
    on_critical: pagerduty://
```

### What This Unlocks

| Capability | Current Raphael | With F2 |
|-----------|----------------|---------|
| Trigger pentest from CI | ❌ | `raphael-ci engage run` |
| Programmatic result consumption | ❌ | JSON/SARIF/JUnit reports |
| Block deployment on critical findings | ❌ | Exit code 1 + webhook |
| Headless API mode | ❌ | `RAPHAEL_MODE=headless` |
| Per-commit security gating | ❌ | GitHub Actions/GitLab CI/Jenkins |
| Async webhook delivery | ❌ | POST results to Slack, PagerDuty, etc. |

---

## Implementation Order

| Phase | What | Files | Effort | Prerequisites |
|-------|------|-------|--------|---------------|
| **F1a** | Base agent class + message bus | `orchestrator/agents/base.py`, `bus.py`, `supervisor.py` | 3 days | — |
| **F1b** | Orchestrator agent + goal decomposition | `orchestrator/agents/orchestrator.py` | 2 days | F1a |
| **F1c** | ReconAgent + ScanAgent | `orchestrator/agents/recon.py`, `scan.py` | 2 days | F1a |
| **F1d** | ExploitAgent + PostExAgent | `orchestrator/agents/exploit.py`, `postex.py` | 2 days | F1a |
| **F1e** | Knowledge graph memory layer | `orchestrator/agents/memory.py` | 3-4 days | F1a, Neo4j running |
| **F1f** | Wire into REPL + agent dashboard | `raphael_cli.py` (/agent-engage, /agent-dashboard) | 2 days | F1a-F1e |
| **F2a** | Headless API server + endpoints | `orchestrator/api/ci.py`, `docker/api.Dockerfile` | 2 days | — |
| **F2b** | `raphael-ci` CLI tool | `cli/raphael_ci.py`, `setup.py` | 2 days | F2a |
| **F2c** | CI pipeline templates | `.github/workflows/raphael-pentest.yml`, `Jenkinsfile`, `.gitlab-ci.yml` | 1 day | F2b |
| **F2d** | Scope enforcement + webhooks | `orchestrator/scope.py`, `orchestrator/webhook.py` | 1 day | F2a |
| **Total** | | | **~20 days** | |

### Quick Win (Day 1)

The fastest path to CI/CD is to expose the existing phase engine via a REST endpoint. This doesn't require the full agent architecture:

```python
# orchestrator/api/quickci.py — wrapper around existing phase engine
@app.post("/v1/ci/scan")
async def quick_scan(target: str):
    """Run recon + scan phases, return structured findings immediately."""
    findings = []
    recon = ReconExecutor()
    scan = ScanExecutor()
    recon_findings = await recon.execute(target)
    scan_findings = await scan.execute(target, {"recon": recon_findings})
    return {"target": target, "findings": recon_findings + scan_findings}
```

Mount this in the existing brain API, and CI pipelines can `curl` it today.

---

## Current Progress

| Phase | What | Status | Files |
|-------|------|--------|-------|
| **Phase 0** | EventBus, scope, sandbox | ✅ Done | `orchestrator/events.py`, `scope.py`, `sandbox.py` |
| **Phase 1a** | CI/CD API + CLI tool | ✅ Done | `orchestrator/api/ci.py`, `api/main.py`, `cli/raphael_ci.py`, `docker/api.Dockerfile` |
| **Phase 1b** | Persona wiring | ✅ Done | `providers.py:resolve_persona_override()`, wired into `autonomous.handle()`, `EngagementQueue`, API endpoints |
| **Phase 1c** | CI templates | ✅ Done | `.github/workflows/raphael-pentest.yml`, `ci-templates/.gitlab-ci.yml`, `ci-templates/Jenkinsfile`, `raphael-scope.yml.example` |
| **Phase 1d** | Hardening + audit logging | ⬜ Pending | Auth hardening, rate limiting, audit trail |

### Commit History

```
8fb3b27  Phase 0 + Phase 1a + Phase 1b — full F2 infrastructure with persona wiring
51b6dbb  checkpoint before F2 CI/CD integration
e8ef1f7  Add P18 (Operational Safety) + P19 (RSI Safety)
```

---



## Summary

| Upgrade | Replaces/Enhances | Gives Raphael |
|---------|------------------|---------------|
| **F1 — Multi-Agent** | Single REPL + deterministic phases | Parallel agent execution, dynamic goal replanning, cross-session learning, custom exploit generation, fault isolation |
| **F2 — CI/CD** | Interactive-only CLI | REST API, CI CLI tool, SARIF/JUnit exports, webhook delivery, pipeline templates for GitHub/GitLab/Jenkins |
