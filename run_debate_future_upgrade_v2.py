#!/usr/bin/env python3
"""
Debate v2: Kimi + Gemma4 + Me (assistant) on whether F1/F2 are worth it,
and if so, produce a detailed integration plan with cross-verification.
"""
import asyncio, json, sys, time, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator.providers import call_model

FUTURE_UPGRADE = (Path(__file__).resolve().parent / "future_upgrade.md").read_text()

# Load the critique synthesis from v1
CRITIQUE_SYNTHESIS_PATH = Path(__file__).resolve().parent / "debate_future_upgrade.json"
CRITIQUE_SYNTHESIS = "No prior critique available."
if CRITIQUE_SYNTHESIS_PATH.exists():
        try:
            data = json.loads(CRITIQUE_SYNTHESIS_PATH.read_text())
            CRITIQUE_SYNTHESIS = data.get("final_synthesis", CRITIQUE_SYNTHESIS)
        except Exception:
            pass

ROUND1_QUESTION = f"""We are evaluating whether to invest in two major upgrades for Raphael, an autonomous pentesting platform.

=== EXISTING DOCUMENT ===
{FUTURE_UPGRADE}
=== END DOCUMENT ===

=== PRIOR CRITIQUE SYNTHESIS ===
{CRITIQUE_SYNTHESIS[:4000]}
=== END PRIOR CRITIQUE ===

Answer two questions:

## Q1: Are these 2 additions worth it?
State clearly: YES, NO, or YES_WITH_MODIFICATIONS — and why.

## Q2: Produce a detailed integration plan.
Assume the answer is YES. Give a concrete, step-by-step plan for integrating F1 (Multi-Agent) and F2 (CI/CD) into the EXISTING Raphael codebase. The plan must address EVERY critique from the prior synthesis:

1. GoalTree validation with deterministic fallback
2. Bounded, async memory (Neo4j + pgvector writes with size caps, batching)
3. MessageBus with back-pressure, dead-letter queues, livelock detection
4. Progress-metric-based fault isolation (not just timeouts)
5. Sandbox for LLM-generated exploit code
6. CI/CD API hardening (mTLS/OIDC, JWT, input validation, scope enforcement)
7. Stealth/noise-budget mechanism
8. HITL approval gates + state checkpointing
9. Agent loop iteration caps + heartbeat
10. Least-privilege agent roles

For EACH item, specify:
- File path(s) to create or modify
- Class/function signatures
- How it wires into existing code (raphael_cli.py, providers.py, brain/api.py, agents/, etc.)
- Estimated lines of code
- Priority (P0/P1/P2)
- Dependencies between items

Be concrete. No vague statements. Give actual Python signatures and integration points."""

ROUND2_QUESTION = """Below are three independent responses to the F1/F2 evaluation question — from Kimi, Gemma4, and a human architect (Me).

=== KIMI'S PLAN ===
{kimi_r1}

=== GEMMA4'S PLAN ===
{gemma4_r1}

=== ME (HUMAN ARCHITECT)'S PLAN ===
{me_r1}

Your job: Produce a REFINED analysis that identifies:
1. AGREEMENT — where all three converge
2. DISAGREEMENT — where you differ from the others, and why you think your position is correct
3. INTEGRATION — specific elements from each plan that should be merged into the final design
4. FINAL VERDICT — one unified integration plan that takes the best from all three

Output as structured JSON with the keys: agreement, disagreement, integration_merges, final_plan"""

FINAL_SYNTHESIS_PROMPT = """Below are refined responses from all three participants after seeing each other's plans.

=== KIMI REFINED ===
{kimi_r2}

=== GEMMA4 REFINED ===
{gemma4_r2}

=== ME (HUMAN ARCHITECT) REFINED ===
{me_r2}

Produce the ABSOLUTE FINAL integration plan. Be decisive. Merge the best of all three.

Output valid JSON:
{{
  "verdict": "YES, invest in both" | "YES, but only F2 first" | "NO",
  "unified_plan": {{
    "summary": "1-2 paragraph summary",
    "phases": [
      {{
        "phase": 1,
        "name": "...",
        "items": [
          {{"file": "...", "action": "create/modify", "detail": "...", "priority": "P0", "loc_estimate": 50}}
        ],
        "estimated_days": 3,
        "gate": "what must be true before next phase"
      }}
    ],
    "total_estimated_days": 55,
    "dependencies": {{"item": ["dep1", "dep2"]}}
  }},
  "key_tradeoffs": ["tradeoff1", "tradeoff2"],
  "what_to_skip": ["things that look good but aren't worth it"],
  "integration_wiring": "How this wires into raphael_cli.py, providers.py, brain/api.py at a high level"
}}
"""


async def call_model_with_timeout(model, messages, max_tokens=8192, temperature=0.7, timeout=300):
    t0 = time.time()
    try:
        result = await asyncio.wait_for(
            call_model(model, messages, max_tokens=max_tokens, temperature=temperature),
            timeout=timeout
        )
        elapsed = time.time() - t0
        return result, elapsed
    except asyncio.TimeoutError:
        return f"[TIMEOUT after {timeout}s]", timeout
    except Exception as e:
        return f"[ERROR: {e}]", time.time() - t0


def my_plan() -> str:
    """My judgement as the human architect / assistant."""
    return """## My Judgement: YES_WITH_MODIFICATIONS

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
"""


async def main():
    print("=" * 70)
    print("DEBATE v2: Kimi + Gemma4 + Me — Worth it? Integration Plan?")
    print("=" * 70)

    models = ["kimi", "gemma4"]
    contributions = {}
    models_r1_done = {}

    # Round 1: Kimi + Gemma4 give verdicts + plans
    print("\n▶ ROUND 1: Independent verdicts + integration plans\n")
    tasks = []
    for model in models:
        tasks.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": ROUND1_QUESTION}],
            max_tokens=8192, temperature=0.7, timeout=600
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks)):
        name = models[i]
        contributions[name] = result
        models_r1_done[name] = True
        print(f"  {name} done ({elapsed:.0f}s) — {len(str(result))} chars")

    # My plan (generated inline above)
    me_plan = my_plan()
    contributions["me"] = me_plan
    print(f"  Me (assistant) done — {len(me_plan)} chars")

    # Show summaries
    for name in ["kimi", "gemma4", "me"]:
        text = str(contributions.get(name, ""))
        label = f"{name.upper()} ROUND 1"
        print(f"\n{'─'*60}")
        print(f"{label} (first 1500 chars)")
        print(f"{'─'*60}")
        print(text[:1500])

    # Round 2: Cross-pollination
    print("\n\n▶ ROUND 2: Cross-pollination & Refinement\n")

    r2_models = ["kimi", "gemma4"]
    kimi_r1 = str(contributions.get("kimi", ""))
    gemma4_r1 = str(contributions.get("gemma4", ""))
    me_r1 = str(contributions.get("me", ""))

    cross_prompt = ROUND2_QUESTION.format(
        kimi_r1=kimi_r1[:5000],
        gemma4_r1=gemma4_r1[:5000],
        me_r1=me_r1[:5000],
    )

    tasks2 = []
    for model in r2_models:
        tasks2.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": cross_prompt}],
            max_tokens=4096, temperature=0.5, timeout=300
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks2)):
        name = r2_models[i]
        contributions[f"{name}_r2"] = result
        print(f"  {name} round 2 done ({elapsed:.0f}s) — {len(str(result))} chars")

    # My refined response
    me_r2 = """## My Refined Response (After Seeing Kimi + Gemma4)

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
- Skip Neo4j until v2 (gemma4 + me agree; kimi conceded)"""

    contributions["me_r2"] = me_r2
    print(f"  Me (assistant) round 2 done — {len(me_r2)} chars")

    for name in ["kimi", "gemma4", "me"]:
        text = str(contributions.get(f"{name}_r2", str(contributions.get(name, ""))))
        label = f"{name.upper()} ROUND 2"
        print(f"\n{'─'*60}")
        print(f"{label} (first 1200 chars)")
        print(f"{'─'*60}")
        print(text[:1200])

    # Round 3: Final synthesis by kimi
    print("\n\n▶ ROUND 3: Final Synthesis (Kimi)\n")

    synthesis_prompt = FINAL_SYNTHESIS_PROMPT.format(
        kimi_r2=str(contributions.get("kimi_r2", ""))[:6000],
        gemma4_r2=str(contributions.get("gemma4_r2", ""))[:6000],
        me_r2=me_r2[:6000],
    )

    final, elapsed = await call_model_with_timeout(
        "kimi",
        [{"role": "user", "content": synthesis_prompt}],
        max_tokens=8192, temperature=0.2, timeout=300
    )
    print(f"  kimi synthesis done ({elapsed:.0f}s) — {len(str(final))} chars")

    # Save everything
    report = {
        "round1": {"kimi": kimi_r1, "gemma4": gemma4_r1, "me": me_r1},
        "round2": {"kimi_r2": str(contributions.get("kimi_r2", "")), "gemma4_r2": str(contributions.get("gemma4_r2", "")), "me_r2": me_r2},
        "final_synthesis": str(final),
        "timestamp": time.time(),
    }
    out_path = Path("debate_future_upgrade_v2.json")
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nFull debate saved to {out_path}")

    # Save readable markdown
    md = f"""# Debate v2: Kimi + Gemma4 + Me — F1/F2 Worth It? Integration Plan

Generated: {time.ctime()}

---

## Kimi Round 1 (Verdict + Plan)

{kimi_r1}

---

## Gemma4 Round 1 (Verdict + Plan)

{gemma4_r1}

---

## Me (Assistant) Round 1

{me_r1}

---

## Kimi Round 2 (Refinement)

{contributions.get('kimi_r2', '')}

---

## Gemma4 Round 2 (Refinement)

{contributions.get('gemma4_r2', '')}

---

## Me Round 2 (Refinement)

{me_r2}

---

## Final Synthesis (Kimi)

{final}
"""
    md_path = Path("debate_future_upgrade_v2.md")
    md_path.write_text(md)
    print(f"\nReadable report saved to {md_path}")

    print("\n" + "=" * 70)
    print("FINAL SYNTHESIS (KIMI)")
    print("=" * 70)
    print(str(final)[:5000])


if __name__ == "__main__":
    asyncio.run(main())
