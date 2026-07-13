#!/usr/bin/env python3
"""
Community design discussion: kimi + gemma4 debate the Phase 3-5 architecture,
then kimi synthesizes. Implements based on consensus.
"""
import asyncio, json, sys, time, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config.paths import get_base_dir

from orchestrator.providers import call_model

DESIGN_QUESTION = """We are designing Raphael 2.0's next evolution (Phases 3-5: Hardening, Advanced Autonomy, Maturity).

We need consensus on three architectural decisions:

## Decision 1: Proxy Strategy System
We need a `ProxyStrategy` enum (DIRECT, VPN, TOR, ACADEMIC, MULTI) and `ProxyGuard` class that:
- Auto-detects available proxy methods (test VPN → test Tor → fallback to chaining)
- Renews Tor circuits via control port
- Supports chaining multiple proxies (Tor → VPN)
- Has health checks and rotation

Should this be a simple enum + class, or should we model it as a state machine with transitions?
Should proxy chaining be sequential (Tor over VPN) or parallel (multi-path)?

## Decision 2: Attack Graph / Target State
We need a `TargetState` class using networkx.DiGraph that:
- Tracks attack paths (start → end with technique + success probability)
- Bayesian updates on success/failure
- Risk scoring per path
- Tracks what's compromised

Is networkx the right choice, or too heavyweight? Should we use a simpler dict-based DAG?
How should the attack graph inform model selection and technique prioritization?

## Decision 3: WAF Bypass Knowledge
We need to extend the RAG knowledge base with:
- ModSecurity CRS evasion techniques (padding, HPP, charset tricks, comment injection)
- Oracle-specific bypasses (XMLType, JSON functions)
- Recent CRS CVE-based bypasses

What's the best structure? Per-DB-type corpus? Per-WAF-rule corpus? CVE-indexed?
How should this integrate with the exploit generation phase?

## Integration Context
- autonomous.py: TargetState should guide phase selection and technique choice
- code_verifier.py: Should score for WAF evasion + stealth, not just syntax
- proxy_guard.py: Must be callable from any phase for on-demand rotation

Please provide:
1. Your recommended architecture for each decision
2. Specific API/interface designs
3. Priority order (P0/P1/P2)
4. What to AVOID (anti-patterns)
5. Integration points with existing code"""

ROUND2_QUESTION = """Now that you've seen the other model's analysis, produce a REFINED consensus.
Identify where you agree, where you disagree, and why.

For each decision, state:
- AGREEMENT: What both of you got right
- REFINEMENT: What the other model missed or got wrong
- FINAL RECOMMENDATION: The merged, strongest approach

Be specific about API signatures, class names, file paths.
Output a single unified design specification."""

async def call_model_with_timeout(model, messages, max_tokens=4096, temperature=0.7, timeout=120):
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

async def main():
    print("=" * 70)
    print("COMMUNITY: Kimi + Gemma4 Design Consensus")
    print("=" * 70)

    models = ["kimi", "gemma4"]
    contributions = {}

    # Round 1: Independent proposals
    print("\n▶ ROUND 1: Independent analysis\n")
    tasks = []
    for model in models:
        tasks.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": DESIGN_QUESTION}],
            max_tokens=4096, temperature=0.7, timeout=180
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks)):
        name = models[i]
        contributions[name] = result
        print(f"  {name} done ({elapsed:.0f}s) — {len(str(result))} chars")

    # Show round 1 summaries
    for name in models:
        text = str(contributions.get(name, ""))
        print(f"\n{'─'*60}")
        print(f"{name.upper()} ROUND 1 (first 1000 chars)")
        print(f"{'─'*60}")
        print(text[:1000])

    # Round 2: Cross-pollination
    print("\n\n▶ ROUND 2: Cross-pollination & Refinement\n")
    
    cross_prompt = ROUND2_QUESTION + "\n\n=== KIMI'S PROPOSAL ===\n" + str(contributions.get("kimi", ""))[:4000] + \
                   "\n\n=== GEMMA4'S PROPOSAL ===\n" + str(contributions.get("gemma4", ""))[:4000]

    tasks2 = []
    for model in models:
        tasks2.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": cross_prompt}],
            max_tokens=4096, temperature=0.5, timeout=180
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks2)):
        name = models[i]
        contributions[f"{name}_r2"] = result
        print(f"  {name} round 2 done ({elapsed:.0f}s) — {len(str(result))} chars")

    for name in models:
        text = str(contributions.get(f"{name}_r2", ""))
        print(f"\n{'─'*60}")
        print(f"{name.upper()} ROUND 2 (first 800 chars)")
        print(f"{'─'*60}")
        print(text[:800])

    # Final synthesis by kimi
    print("\n\n▶ ROUND 3: Kimi Final Synthesis\n")
    
    all_content = f"=== KIMI ROUND 1 ===\n{contributions.get('kimi','')}\n\n" + \
                  f"=== GEMMA4 ROUND 1 ===\n{contributions.get('gemma4','')}\n\n" + \
                  f"=== KIMI ROUND 2 (refinement) ===\n{contributions.get('kimi_r2','')}\n\n" + \
                  f"=== GEMMA4 ROUND 2 (refinement) ===\n{contributions.get('gemma4_r2','')}\n\n"

    final_prompt = f"""You are the lead architect. All community contributions are below.

{all_content}

Your job: Produce the FINAL definitive design specification that will guide implementation.

Output must be in this format:

```json
{{
  "decisions": {{
    "proxy_strategy": {{
      "recommendation": "...",
      "class_name": "ProxyGuard",
      "methods": ["detect_and_rotate", "renew_tor_circuit", "health_check", "chain_proxies"],
      "priority": "P0",
      "anti_patterns": ["..."],
      "file": "orchestrator/modules/proxy_guard.py"
    }},
    "attack_graph": {{
      "recommendation": "...",
      "class_name": "TargetState",
      "methods": ["add_path", "update_from_result", "get_riskiest_path", "compromise"],
      "priority": "P1",
      "anti_patterns": ["..."],
      "file": "orchestrator/brain/target_state.py"
    }},
    "waf_bypass": {{
      "recommendation": "...",
      "structure": "...",
      "priority": "P1",
      "anti_patterns": ["..."],
      "file": "orchestrator/brain/rag_knowledge.py"
    }},
    "integration": {{
      "autonomous_changes": "...",
      "code_verifier_changes": "...",
      "priority_order": ["proxy_guard", "target_state", "waf_bypass", "integration"]
    }}
  }}
}}
```

Be specific. Give actual class signatures and method signatures."""
    
    final, elapsed = await call_model_with_timeout(
        "kimi",
        [{"role": "user", "content": final_prompt}],
        max_tokens=8192, temperature=0.2, timeout=300
    )
    print(f"  kimi synthesis done ({elapsed:.0f}s) — {len(str(final))} chars")

    # Save everything
    report = {
        "round1": {k: str(contributions.get(k, "")) for k in models},
        "round2": {f"{k}_r2": str(contributions.get(f"{k}_r2", "")) for k in models},
        "final_synthesis": str(final),
        "timestamp": time.time(),
    }
    out_path = get_base_dir() / "community_consensus_design.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nFull report saved to {out_path}")

    # Print final synthesis
    print("\n" + "="*70)
    print("FINAL SYNTHESIS (KIMI)")
    print("="*70)
    print(str(final)[:3000])

if __name__ == "__main__":
    asyncio.run(main())
