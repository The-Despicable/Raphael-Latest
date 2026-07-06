#!/usr/bin/env python3
"""RSI-style paper analysis: 3 models + kimi synthesis.
Phase 1: independent analysis (parallel), Phase 2: cross-critique, Phase 3: kimi synthesis.
Uses direct httpx to NVIDIA API (opencode CLI has routing issues with NVIDIA)."""

import asyncio, json, httpx, time, sys, os

API_BASE = "https://integrate.api.nvidia.com/v1"
API_KEY = os.getenv("NVIDIA_API_KEY")
if not API_KEY:
    raise RuntimeError("NVIDIA_API_KEY environment variable required")

TEAM = {
    "kimi": "moonshotai/kimi-k2.6",
    "nemotron-super": "nvidia/llama-3.3-nemotron-super-49b-v1",
    "mistral-675b": "mistralai/mistral-large-3-675b-instruct-2512",
}

PAPER_PATH = os.getenv("PAPER_TEXT_PATH", "/tmp/paper_text.txt")
PAPER_TEXT = open(PAPER_PATH).read()
MARKER = "===PAPER_BELOW==="

TASK = f"""You are a critical reviewer analyzing the following academic paper. Your job is to provide a thorough, rigorous analysis.

{MARKER}
{PAPER_TEXT}
{MARKER}

Your analysis MUST cover these dimensions:

1. SUMMARY — What is the paper's core claim or contribution? (2-3 sentences)
2. SCIENTIFIC RIGOR — Evaluate methodology, evidence quality, logical reasoning. Are the claims supported?
3. STRENGTHS — What does this paper do well?
4. WEAKNESSES — What are the flaws, gaps, or overreaches?
5. NOVELTY — Is there anything new here, or is it restating known ideas?
6. APPLICABILITY — How useful is this for practitioners (especially those building LLM-based systems)?
7. DUNNING-KRUGER CLAIM — The paper applies the Dunning-Kruger effect to AI usage in scientific writing. Evaluate the validity of this analogy.
8. THE LSD ANECDOTE — The paper uses the Kary Mullis LSD story as a closing analogy. Is this appropriate for a scientific correspondence?
9. WRITING QUALITY — Clarity, structure, tone, persuasiveness
10. FINAL VERDICT — Overall assessment (Strong Accept / Accept / Minor Revision / Major Revision / Reject) with justification.

Be specific. Quote passages. Don't be polite — be honest about flaws."""

SYNTHESIS_TASK = """You are the lead reviewer synthesizing a team's independent analyses of a paper.

THE ACTUAL PAPER TEXT IS INCLUDED BELOW. It IS a real published correspondence.
===PAPER===
{PAPER_TEXT}
===PAPER_END===

TEAM MEMBER ANALYSES:
{d}

YOUR JOB: Produce the FINAL REVIEW REPORT. Include:
1. A summary table of each team member's verdict and key points
2. Where they agreed and disagreed
3. Your own final assessment — decide which analyses were most accurate and which were wrong
4. A unified final review with ALL 10 dimensions covered
5. A single FINAL VERDICT

Be decisive. One unified recommendation. No hedging."""

async def call_model(model_id, prompt, temperature=0.3, max_tokens=4096):
    async with httpx.AsyncClient(timeout=300) as cl:
        resp = await cl.post(
            f"{API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False,
            }
        )
        body = resp.json()
        if "choices" not in body:
            return f"ERROR: {json.dumps(body)[:500]}"
        return body["choices"][0]["message"]["content"]

async def main():
    team_list = list(TEAM.items())
    print("=" * 70)
    print("RSI PAPER ANALYSIS: Salvagno et al. 'Artificial intelligence hallucinations'")
    print(f"Team: {', '.join(TEAM.keys())}")
    print("=" * 70 + "\n")

    all_results = {}

    # Phase 1: All models analyze independently in parallel
    print("Phase 1: Independent Analysis\n")
    t0_total = time.time()

    async def analyze_one(name, model_id):
        t0 = time.time()
        result = await call_model(model_id, TASK, temperature=0.4)
        elapsed = time.time() - t0
        print(f"  {name} done ({elapsed:.0f}s)")
        return name, result

    tasks = [analyze_one(name, mid) for name, mid in team_list]
    done = await asyncio.gather(*tasks)

    for name, result in done:
        all_results[name] = result
        lines = result.strip().split('\n')
        print(f"\n  --- {name} (first 3 lines) ---")
        for l in lines[:3]:
            print(f"  {l[:120]}")

    print("\n" + "=" * 70)
    print("Phase 2: Cross-Critique\n")

    critique_text = ""
    for name, text in all_results.items():
        critique_text += f"\n=== {name} ===\n{text}\n"

    critique_prompt = f"""You are evaluating analyses of a real paper. The paper text is included below for reference.

THE ACTUAL PAPER:
{MARKER}
{PAPER_TEXT}
{MARKER}

TEAM MEMBER ANALYSES:
{critique_text}

Now give a CRITIQUE:
1. Which analysis is most accurate? Which is wrong?
2. Where do they agree? Where do they disagree?
3. What did each model miss?
4. Give your UPDATED assessment after reading the others.

IMPORTANT: The paper above IS real. Your job is to evaluate the analyses against it, not to question whether the paper exists.
"""

    async def critique_one(name, model_id):
        t0 = time.time()
        result = await call_model(model_id, critique_prompt, temperature=0.3, max_tokens=2048)
        elapsed = time.time() - t0
        print(f"  {name} critique done ({elapsed:.0f}s)")
        return name, result

    critiques = await asyncio.gather(*[critique_one(name, mid) for name, mid in team_list])
    for name, text in critiques:
        all_results[f"{name}_critique"] = text

    print("\n" + "=" * 70)
    print("Phase 3: Final Synthesis (kimi)\n")

    synthesis_input = ""
    for name, text in all_results.items():
        synthesis_input += f"\n=== {name} ===\n{text}\n"

    final = await call_model(
        TEAM["kimi"],
        SYNTHESIS_TASK.format(PAPER_TEXT=PAPER_TEXT, d=synthesis_input),
        temperature=0.2,
        max_tokens=4096
    )

    elapsed_total = time.time() - t0_total
    print(final)
    print("\n" + "=" * 70)
    print(f"Total time: {elapsed_total:.0f}s")
    print("Saving reports...")

    report = {
        "paper": "Salvagno et al. 'Artificial intelligence hallucinations' (Critical Care, 2023)",
        "team": TEAM,
        "phase1_individual": {k: all_results[k] for k in TEAM},
        "phase2_critiques": {k: all_results[f"{k}_critique"] for k in TEAM if f"{k}_critique" in all_results},
        "phase3_synthesis": final,
    }

    with open("rsi_paper_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("Saved to rsi_paper_report.json")

    with open("rsi_paper_report_final.md", "w") as f:
        f.write(final)
    print("Saved to rsi_paper_report_final.md")

asyncio.run(main())
