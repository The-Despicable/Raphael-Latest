#!/usr/bin/env python3
"""Debate: Reasoning Team's fix plan vs My fix plan — W12 vs W13, 3 rounds."""
import asyncio, json, sys, time
sys.path.insert(0, '.')
from orchestrator.providers import _call_model_raw

REASONING_TEAM_PLAN = open("reasoning_team_final_plan.md").read()[:4000]
MY_PLAN = open("my_fix_plan.md").read()[:3000]

QUESTION = f"""DEBATE: Which fix plan should be applied to the Raphael 2.0 autonomous AI security platform?

Plan A (Reasoning Team): Heavyweight, comprehensive. Uses Vault for secrets management, mmap for memory-only tokens, full CSP-style command whitelisting, SSLContext-based TLS hardening, complete architectural rewrites. Requires running a HashiCorp Vault server as external infrastructure.

Key excerpts from Plan A:
{REASONING_TEAM_PLAN}

Plan B (My Plan): Pragmatic, minimum viable changes. Runtime env vars instead of Vault, JSON config files instead of code generation, shell=False + regex instead of full command dispatcher, tmpfs + atexit + shred for forensics instead of mmap, confirmation prompts instead of architectural opsec rewrites. ~50% less code, no external infrastructure.

Key excerpts from Plan B:
{MY_PLAN}

Debate criteria:
1. SECURITY — Which leaves fewer remaining vulnerabilities?
2. PRACTICALITY — Which can be implemented correctly with less risk of new bugs?
3. MAINTAINABILITY — Which creates less ongoing burden?
4. DEPENDENCIES — Which has fewer/lighter external dependencies?
5. FIT — Which is more appropriate for a research/offensive security tool?

W12 (Plan A) and W13 (Plan B), 3 rounds. Each round bring NEW arguments."""

async def call_model_safe(model_alias, messages, temperature=0.85, max_tokens=4096):
    try:
        return await asyncio.wait_for(
            _call_model_raw(model_alias, messages, temperature=temperature, max_tokens=max_tokens),
            timeout=300
        )
    except asyncio.TimeoutError:
        return f"[TIMEOUT]"
    except Exception as e:
        return f"[ERROR: {e}]"

async def main():
    print("=" * 60)
    print("FIX PLAN DEBATE — W12 (Plan A) vs W13 (Plan B)")
    print("3 rounds + synthesis")
    print("=" * 60)

    history = {"w12": "", "w13": ""}

    for r in range(1, 4):
        temp = 0.85 + (r - 1) * 0.05
        print(f"\n--- ROUND {r}/3 ---", flush=True)

        if r == 1:
            ctx_a = f"[ROUND 1/3]\nQuestion: {QUESTION}\n\nYou are W12. Defend Plan A (Reasoning Team's approach — Vault, mmap, CSP whitelists). State why its comprehensive approach is necessary despite the heavier weight."
            ctx_b = f"[ROUND 1/3]\nQuestion: {QUESTION}\n\nYou are W13. Defend Plan B (My pragmatic approach — env vars, JSON configs, shell=False, tmpfs). You just saw W12's argument for Plan A. Critique it and present why Plan B is superior."
        else:
            prev_a = history.get("w12", "")[-2000:]
            prev_b = history.get("w13", "")[-2000:]
            ctx_a = f"[ROUND {r}/3]\nQuestion: {QUESTION}\n\nPrevious W13 (Plan B) arguments:\n{prev_b}\n\nYou are W12. Bring NEW arguments for Plan A that haven't been mentioned. Attack specific weaknesses in Plan B's pragmatic approach."
            ctx_b = f"[ROUND {r}/3]\nQuestion: {QUESTION}\n\nPrevious W12 (Plan A) arguments:\n{prev_a}\n\nYou are W13. Bring NEW arguments for Plan B that haven't been mentioned. Attack specific over-engineering in Plan A."

        # Round: W12 speaks first
        print(f"  W12 (Plan A) debating...", flush=True)
        r12 = await call_model_safe("w12", [{"role": "user", "content": ctx_a}], temperature=temp)
        history["w12"] = r12
        print(f"    {len(r12)} chars", flush=True)

        # Then W13 responds
        print(f"  W13 (Plan B) countering...", flush=True)
        ctx_b_full = ctx_b + f"\n\nW12 just argued:\n{r12[:3000]}"
        r13 = await call_model_safe("w13", [{"role": "user", "content": ctx_b_full}], temperature=temp)
        history["w13"] = r13
        print(f"    {len(r13)} chars", flush=True)

    # Synthesis
    print(f"\n--- SYNTHESIS ---", flush=True)
    synthesis_prompt = f"""Question: {QUESTION}

Full debate history:

=== W12 (Plan A) FINAL ===
{history['w12'][:4000]}

=== W13 (Plan B) FINAL ===
{history['w13'][:4000]}

Synthesize the debate into a decisive verdict. Which plan won and why? Then produce a MIXED plan that takes the BEST elements from each. Be specific about what to adopt from each plan.

Output format:
1. WINNER: [Plan A / Plan B / Hybrid]
2. Key reason:
3. Adopted from Plan A (list specific items):
4. Adopted from Plan B (list specific items):
5. Final ordered fix list (by priority):"""
    
    final = await call_model_safe("w13", [{"role": "user", "content": synthesis_prompt}], temperature=0.3)
    print(f"  Synthesis: {len(final)} chars", flush=True)

    # Save
    output = {**history, "synthesis": final}
    with open("fixplan_debate_result.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print("DEBATE COMPLETE")
    print(f"  W12 (Plan A) final: {len(history['w12'])} chars")
    print(f"  W13 (Plan B) final: {len(history['w13'])} chars")
    print(f"  Synthesis: {len(final)} chars")
    print(f"{'='*60}")
    print("\n=== SYNTHESIS ===\n")
    print(final[:3000])
    print(f"\n... (full in fixplan_debate_result.json)")

if __name__ == "__main__":
    asyncio.run(main())
