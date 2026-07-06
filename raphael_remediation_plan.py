#!/usr/bin/env python3
"""Ask Kimi and Gemma4 to produce a combined fix/upgrade plan for Raphael 2.0."""
import asyncio, json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from orchestrator.providers import call_model

AUDIT_FINDINGS = """You are a security architect and remediation planner. Below is a full audit of Raphael 2.0, with critical findings across 8 categories.

---

## Critical Issues Requiring Fix

### 🔴 CRITICAL (7 items)

1. **NVIDIA API key hard-coded in 6 files** — `rsi_team_analysis.py`, `rsi_paper_analysis.py`, `rsi_redteam_port.py`, `rsi_hermes_ui.py`, `community_implement.py`, `debate_claude_clone.py` have leaked `nvapi-...` keys. Two have no env-var fallback.
2. **No test suite** — only 4/58 files have `__main__` verification. Bayesian bandit, proxy circuit isolation, code verifier have zero unit tests.
3. **Kill-switch is orphaned** — `_check_iptables_kill_switch()` only called in unreachable `else` branch in proxy_guard.py. FAIL-DEAD may be a no-op.
4. **Dead proxy fallback chain** — WireGuard, FlareTunnel, VPNBook, dnscrypt, iptables checks in proxy_guard.py:240-256 unreachable.
5. **8 hard-coded `/home/yaser/` absolute paths** in 3 files.
6. **12+ bare `except:` clauses** swallowing KeyboardInterrupt/SystemExit.
7. **Duplicate brain route** — `GET /v1/brain/state` defined twice in brain/api.py.

### 🟡 Dead Code (5 items)

8. `real_tools.py`: 3 dead classes never imported anywhere.
9. Unreachable proxy fallback chain (above).
10. 8 unused imports in modes/autonomous.py.
11. Stale bytecode: orphaned hrm_plan.pyc with no source.
12. Duplicate CLI file: raphael_cli.py and raphael-cli.py side by side.

### 🟢 Architecture Gaps (6 items)

13. No graceful degradation when all LLM providers fail — framework stops.
14. 14-40s latency per LLM decision — 7-phase engagement takes hours.
15. No target environment state model — system has no memory of what it learns.
16. Behavioral mimicry hard-coded to IST, not geo-located to target.
17. Telegram bot for C2 — Telegram cooperates with LE, not E2EE in channels.
18. SQLite as inter-service bus — no message queue, no WAL mode for brain.db.

### 🔵 Missing Features (4 items)

19. No adversary simulation profiles (MITRE ATT&CK, Caldera-style).
20. No operator-side audit trail — can't reconstruct hallucinated destructive commands.
21. No CI/CD pipeline or pre-commit hooks.
22. No sandbox for testing generated kernel-level payloads.

---

## Your Task

Produce a **combined fix + upgrade plan** for Raphael 2.0. Structure it as:

### Phase 0: Emergency (do within 24 hours)
What must be fixed immediately to make the tool safe to run.

### Phase 1: Architectural Surgery (1-2 weeks)
What structural changes are needed — which services to merge, which to remove, which abstractions to fix.

### Phase 2: Feature Completion (2-4 weeks)
What missing capabilities to add and in what order.

### Phase 3: Hardening (ongoing)
Testing, CI/CD, monitoring, operational security.

For each item:
- **What** exactly to change (file paths, function names)
- **Why** (the specific failure mode it prevents)
- **Risk** of not doing it
- **Effort** (small/medium/large)

Be concrete — name specific files, functions, and lines. Don't say "fix the proxy layer" — say "remove lines 240-256 in proxy_guard.py, and add a 3-second timeout circuit check after strategy detection at line 214."

This is an engineering remediation plan, not a strategy document."""


async def get_plan(model: str, label: str) -> dict:
    print(f"  Calling {model}...", flush=True)
    t0 = __import__('time').time()
    try:
        response = await asyncio.wait_for(
            call_model(model, [{"role": "user", "content": AUDIT_FINDINGS}], max_tokens=8192, temperature=0.5),
            timeout=300
        )
        elapsed = __import__('time').time() - t0
        print(f"  {model} responded in {elapsed:.0f}s ({len(response)} chars)", flush=True)
        return {"model": model, "label": label, "response": response, "elapsed": round(elapsed, 1), "success": True}
    except Exception as e:
        elapsed = __import__('time').time() - t0
        print(f"  {model} FAILED after {elapsed:.0f}s: {e}", flush=True)
        return {"model": model, "label": label, "error": str(e), "elapsed": round(elapsed, 1), "success": False}


async def main():
    print("=== Raphael 2.0 Fix/Upgrade Plan — Kimi + Gemma4 ===\n")

    results = await asyncio.gather(
        get_plan("kimi", "Kimi (kimi-k2.6 via NVIDIA)"),
        get_plan("gemma4", "Gemma4 (gemma4-31b-think via Ollama API)"),
    )

    path = "raphael_remediation_plan.json"
    with open(path, "w") as f:
        json.dump({"audit": AUDIT_FINDINGS, "plans": results, "timestamp": __import__('time').ctime()}, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to {path}")

    for r in results:
        label = r["label"]
        if r["success"]:
            print(f"\n{'='*60}")
            print(f"{label}  ({r['elapsed']}s, {len(r['response'])} chars)")
            print(f"{'='*60}")
            print(r["response"][:4000])
            if len(r["response"]) > 4000:
                print(f"\n... ({len(r['response']) - 4000} more chars)")
        else:
            print(f"\n{label}: ERROR — {r['error']}")


if __name__ == "__main__":
    asyncio.run(main())
