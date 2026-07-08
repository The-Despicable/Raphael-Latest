#!/usr/bin/env python3
"""
Debate: kimi + gemma4 critique the future_upgrade.md (Multi-Agent + CI/CD).
Two rounds of independent analysis, cross-pollination, then kimi synthesizes.
"""
import asyncio, json, sys, time, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator.providers import call_model

FUTURE_UPGRADE_PATH = Path(__file__).resolve().parent / "future_upgrade.md"
FUTURE_UPGRADE_CONTENT = FUTURE_UPGRADE_PATH.read_text()

CRITIQUE_QUESTION = f"""You are a senior security architect reviewing a proposed upgrade plan for Raphael, an autonomous pentesting platform.

Read the following upgrade document carefully, then provide your critique.

=== DOCUMENT ===
{FUTURE_UPGRADE_CONTENT}
=== END DOCUMENT ===

Evaluate the proposal on these dimensions:

1. **Architectural soundness** — Does the multi-agent design actually improve over the current phase engine? Are there hidden coupling issues, single points of failure, or unnecessary complexity?

2. **Feasibility** — Can this realistically be built in the estimated 20 days? What's the hardest part that will take the longest?

3. **Security & OPSEC concerns** — Does adding agent-to-agent communication introduce new attack surface? Are there prompt injection risks between agents? What about the CI/CD API — auth, rate limiting, data exposure?

4. **Completeness** — What's missing? What attack vector or workflow does this plan overlook?

5. **Priority** — If you could only do one of F1 or F2, which would you pick and why?

6. **Anti-patterns** — What part of this proposal should be avoided or redesigned before implementation?

Be specific. Call out file paths, class names, and concrete risks. This is a technical review, not a summary."""

ROUND2_QUESTION = """Now that you've seen the other model's critique, produce a REFINED analysis.

Identify:
- AGREEMENT: Where do both of you converge?
- DISAGREEMENT: Where do you differ? Why?
- REFINEMENT: What did the other model catch that you missed?
- FINAL VERDICT: For each of the 6 evaluation dimensions, what is the merged, strongest position?

Output a structured JSON verdict."""

SYNTHESIS_PROMPT = """You are the lead architect. Below are two rounds of critique from two senior reviewers (kimi and gemma4) on the Raphael future_upgrade.md.

=== KIMI ROUND 1 ===
{kimi_r1}

=== GEMMA4 ROUND 1 ===
{gemma4_r1}

=== KIMI ROUND 2 (refinement) ===
{kimi_r2}

=== GEMMA4 ROUND 2 (refinement) ===
{gemma4_r2}

Your job: Produce the FINAL definitive verdict that will guide whether and how to implement this plan.

Output must be valid JSON with this structure:
{{
  "verdict": "approved" | "approved_with_changes" | "rejected",
  "changes_required": ["change1", "change2", ...],
  "architectural_score": 1-10,
  "feasibility_score": 1-10,
  "security_score": 1-10,
  "completeness_score": 1-10,
  "top_3_risks": ["risk1", "risk2", "risk3"],
  "top_3_strengths": ["strength1", "strength2", "strength3"],
  "recommended_order": ["F1 first" | "F2 first" | "parallel"],
  "revised_estimate_days": integer,
  "critical_omissions": ["omission1", ...],
  "final_recommendation": "free-form text, 2-3 paragraphs"
}}

Be decisive. The output drives real implementation decisions."""


async def call_model_with_timeout(model, messages, max_tokens=8192, temperature=0.7, timeout=180):
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
    print("DEBATE: Kimi + Gemma4 on future_upgrade.md")
    print("=" * 70)

    models = ["kimi", "gemma4"]
    contributions = {}

    # Round 1: Independent critiques
    print("\n▶ ROUND 1: Independent critique\n")
    tasks = []
    for model in models:
        tasks.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": CRITIQUE_QUESTION}],
            max_tokens=8192, temperature=0.7, timeout=300
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks)):
        name = models[i]
        contributions[name] = result
        print(f"  {name} done ({elapsed:.0f}s) — {len(str(result))} chars")

    # Show round 1 summaries
    for name in models:
        text = str(contributions.get(name, ""))
        print(f"\n{'─'*60}")
        print(f"{name.upper()} ROUND 1 (first 1500 chars)")
        print(f"{'─'*60}")
        print(text[:1500])

    # Round 2: Cross-pollination
    print("\n\n▶ ROUND 2: Cross-pollination & Refinement\n")

    cross_prompt = ROUND2_QUESTION + "\n\n=== KIMI'S CRITIQUE ===\n" + str(contributions.get("kimi", ""))[:5000] + \
                   "\n\n=== GEMMA4'S CRITIQUE ===\n" + str(contributions.get("gemma4", ""))[:5000]

    tasks2 = []
    for model in models:
        tasks2.append(call_model_with_timeout(
            model,
            [{"role": "user", "content": cross_prompt}],
            max_tokens=4096, temperature=0.5, timeout=300
        ))
    for i, (result, elapsed) in enumerate(await asyncio.gather(*tasks2)):
        name = models[i]
        contributions[f"{name}_r2"] = result
        print(f"  {name} round 2 done ({elapsed:.0f}s) — {len(str(result))} chars")

    for name in models:
        text = str(contributions.get(f"{name}_r2", ""))
        print(f"\n{'─'*60}")
        print(f"{name.upper()} ROUND 2 (first 1200 chars)")
        print(f"{'─'*60}")
        print(text[:1200])

    # Final synthesis by kimi
    print("\n\n▶ ROUND 3: Kimi Final Synthesis\n")

    synthesis_prompt = SYNTHESIS_PROMPT.format(
        kimi_r1=str(contributions.get("kimi", ""))[:6000],
        gemma4_r1=str(contributions.get("gemma4", ""))[:6000],
        kimi_r2=str(contributions.get("kimi_r2", ""))[:5000],
        gemma4_r2=str(contributions.get("gemma4_r2", ""))[:5000],
    )

    final, elapsed = await call_model_with_timeout(
        "kimi",
        [{"role": "user", "content": synthesis_prompt}],
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
    out_path = Path("debate_future_upgrade.json")
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nFull debate saved to {out_path}")

    # Print final synthesis
    print("\n" + "=" * 70)
    print("FINAL SYNTHESIS (KIMI)")
    print("=" * 70)
    print(str(final)[:4000])

    # Also save a readable markdown version
    md = f"""# Debate: Kimi + Gemma4 on future_upgrade.md

Generated: {time.ctime()}

---

## Kimi Round 1

{contributions.get('kimi', '')}

---

## Gemma4 Round 1

{contributions.get('gemma4', '')}

---

## Kimi Round 2 (Refinement)

{contributions.get('kimi_r2', '')}

---

## Gemma4 Round 2 (Refinement)

{contributions.get('gemma4_r2', '')}

---

## Final Synthesis (Kimi)

{final}
"""
    md_path = Path("debate_future_upgrade.md")
    md_path.write_text(md)
    print(f"\nReadable report saved to {md_path}")


if __name__ == "__main__":
    asyncio.run(main())
