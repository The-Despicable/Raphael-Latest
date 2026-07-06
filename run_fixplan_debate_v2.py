#!/usr/bin/env python3
"""Debate: Reasoning Team vs My Plan — using only NVIDIA API models (nemotron-super, mistral-large, kimi)."""
import asyncio, json, sys, os, time
sys.path.insert(0, '.')
from orchestrator.providers import _call_model_raw

REASONING_TEAM_PLAN = open("reasoning_team_final_plan.md").read()[:4000]
MY_PLAN = open("my_fix_plan.md").read()[:3000]

QUESTION = f"""Debate: Two fix plans exist for the Raphael 2.0 autonomous AI security platform. Which plan is better?

Plan A (Reasoning Team — "Heavyweight"): Uses Vault for secrets management, mmap for memory-only tokens, CSP-style command whitelisting, full architectural rewrites. Requires external Vault infrastructure. Comprehensive but heavy.

Key excerpts from Plan A:
{REASONING_TEAM_PLAN}

Plan B (My Plan — "Pragmatic"): Uses runtime env vars instead of Vault, JSON config files instead of code generation, shell=False + regex instead of command dispatcher, tmpfs + atexit + shred for forensics. ~50% less code, no external infrastructure.

Key excerpts from Plan B:
{MY_PLAN}

Debate criteria: SECURITY, PRACTICALITY, MAINTAINABILITY, DEPENDENCIES, FIT for research tool."""

async def _call(alias, messages, max_tokens=8192, temperature=0.85, timeout=300):
    t0 = time.time()
    try:
        result = await asyncio.wait_for(
            _call_model_raw(alias, messages, max_tokens=max_tokens, temperature=temperature),
            timeout=timeout
        )
        elapsed = time.time() - t0
        return result, alias, elapsed
    except asyncio.TimeoutError:
        return f"[TIMEOUT after {timeout}s]", alias, timeout
    except Exception as e:
        return f"[ERROR: {e}]", alias, 0

async def main():
    print("=" * 60)
    print("FIX PLAN DEBATE — Nemotron-super (Plan A) vs Mistral-large (Plan B)")
    print("2 rounds + Kimi synthesis")
    print("=" * 60)

    # Plan A defender (reasoning team's approach)
    model_a = "nemotron-super"
    # Plan B defender (my pragmatic approach)
    model_b = "mistral-large"
    # Judge
    judge = "kimi"

    results = {"rounds": []}

    for r in range(1, 3):
        temp = 0.85 if r == 1 else 0.9
        print(f"\n--- Round {r}/2 (temp={temp}) ---", flush=True)

        # Build context with previous round
        ctx_extra = ""
        if results["rounds"]:
            prev = results["rounds"][-1]
            ctx_extra = (
                f"\n\nPrevious round arguments:\n"
                f"<{model_a}>\n{prev[model_a][:3000]}\n</{model_a}>\n"
                f"<{model_b}>\n{prev[model_b][:3000]}\n</{model_b}>\n\n"
                f"You MUST bring NEW arguments not mentioned before. "
                f"Attack the OTHER plan's specific weaknesses."
            )

        # Plan A defender (nemotron-super)
        prompt_a = (
            f"[ROUND {r}/2]\n"
            f"You are defending Plan A (Reasoning Team's approach: Vault, mmap, CSP whitelists, comprehensive rewrites).\n"
            f"Argue why Plan A's heavyweight approach is NECESSARY and Plan B's pragmatic shortcuts are DANGEROUS.\n"
            f"Question: {QUESTION}\n{ctx_extra}"
        )
        result_a, model, elapsed = await _call(model_a, [{"role": "user", "content": prompt_a}], temperature=temp)
        print(f"  {model_a}: {len(result_a)} chars ({elapsed:.0f}s)", flush=True)

        # Plan B defender (mistral-large)
        prompt_b = (
            f"[ROUND {r}/2]\n"
            f"You are defending Plan B (Pragmatic approach: env vars, JSON configs, tmpfs, minimal changes).\n"
            f"You just saw Plan A's argument. Here it is:\n{result_a[:4000]}\n\n"
            f"Argue why Plan A is OVER-ENGINEERED and why Plan B achieves the same security with less complexity.\n"
            f"Critique Plan A's specific choices (Vault, mmap, CSP).\n"
            f"Question: {QUESTION}\n{ctx_extra}"
        )
        result_b, model, elapsed = await _call(model_b, [{"role": "user", "content": prompt_b}], temperature=temp)
        print(f"  {model_b}: {len(result_b)} chars ({elapsed:.0f}s)", flush=True)

        results["rounds"].append({"round": r, model_a: result_a, model_b: result_b})

    # Kimi synthesis — judge decides
    print(f"\n--- Synthesis ---", flush=True)
    final_round = results["rounds"][-1]
    synthesis_input = (
        f"You are the final judge.\n\n"
        f"Question: {QUESTION}\n\n"
        f"Final debate:\n"
        f"<{model_a} (Plan A)>\n{final_round[model_a][:5000]}\n</{model_a}>\n"
        f"<{model_b} (Plan B)>\n{final_round[model_b][:5000]}\n</{model_b}>\n\n"
        f"Decide: Which plan wins? Output a HYBRID plan taking the BEST elements from each.\n"
        f"Format:\n"
        f"1. WINNER: Plan A / Plan B / Hybrid\n"
        f"2. Top 3 decisive reasons\n"
        f"3. Items to adopt from Plan A:\n"
        f"4. Items to adopt from Plan B:\n"
        f"5. Final ordered fix list (all findings) incorporating the best of both:"
    )
    synthesis, model, elapsed = await _call(judge, [{"role": "user", "content": synthesis_input}], temperature=0.3)
    print(f"  {judge}: {len(synthesis)} chars ({elapsed:.0f}s)", flush=True)
    results["synthesis"] = synthesis

    # Save
    with open("fixplan_debate_result.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open("fixplan_debate_verdict.md", "w") as f:
        f.write("# Fix Plan Debate — Verdict\n\n")
        f.write(synthesis)
        f.write("\n\n---\n\n## Full Debate Transcript\n\n")
        for rnd in results["rounds"]:
            f.write(f"### Round {rnd['round']}\n\n")
            f.write(f"**{model_a} (Plan A):**\n\n{rnd[model_a]}\n\n")
            f.write(f"**{model_b} (Plan B):**\n\n{rnd[model_b]}\n\n")

    print(f"\n{'='*60}")
    print("DEBATE COMPLETE")
    print(f"  Saved to: fixplan_debate_verdict.md")
    print(f"  {judge} synthesis: {len(synthesis)} chars")
    print(f"{'='*60}")
    print(f"\n=== VERDICT ===\n")
    print(synthesis[:3000])

if __name__ == "__main__":
    asyncio.run(main())
