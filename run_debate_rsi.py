"""
Debate (glm-5.2 + worm-12 + worm-13 + worm-480b) -> RSI -> Final Plan
gemma4 has weekly quota exceeded (429). Replaced with glm-5.2 for synthesis.
"""

import asyncio, json, sys, os, time

sys.path.insert(0, os.path.dirname(__file__))
from orchestrator.providers import call_model
from orchestrator.conductor import conductor_call

GLM52   = "glm-5.2:cloud"
W12     = "blackgrg26/WORMGPT-12:latest"
W13     = "blackgrg26/WORMGPT-13:latest"
W480B   = "alarksahu388/wormgpt480b:latest"
MISTRAL = "qwelynx/mistral-large-instruct-2407:Q4_K_M"
NEMOTRON = "nemotron-super"

DEBATE_MODELS = {
    "glm-5.2":    GLM52,
    "worm-12":    W12,
    "worm-13":    W13,
    "worm-480b":  W480B,
}

async def debate(model_key, prompt, temperature=0.85, timeout=240):
    model = DEBATE_MODELS[model_key]
    if model_key == "glm-5.2":
        return await conductor_call(model, prompt, category="attack_planning",
                                     max_tokens=8192, temperature=temperature, timeout=timeout)
    return await call_model(model, [{"role": "user", "content": prompt}],
                             max_tokens=8192, temperature=temperature)

async def rsi_phase(question, temperature=0.5):
    ctx_prompt = (
        f"[RSI] Research, Search, Integrate\nBase Task: {question}\n\n"
        f"Phase 1 (Research): Analyze the problem rigorously.\n"
        f"Phase 2 (Search): Verify assumptions, check edge cases.\n"
        f"Phase 3 (Integrate): Produce a complete, proven answer."
    )

    research = {}

    print(f"  RSI critical ({NEMOTRON})... ", end="", flush=True)
    t0 = time.time()
    research["critical"] = await call_model(
        NEMOTRON,
        [{"role": "user", "content": f"[CRITICAL]\n{ctx_prompt}"}],
        max_tokens=8192, temperature=temperature)
    print(f"done ({time.time()-t0:.0f}s) — {len(research['critical'])} chars")

    print(f"  RSI deep_dive ({MISTRAL})... ", end="", flush=True)
    t0 = time.time()
    research["deep_dive"] = await call_model(
        MISTRAL,
        [{"role": "user", "content": f"[DEEP_DIVE]\n{ctx_prompt}"}],
        max_tokens=8192, temperature=temperature)
    print(f"done ({time.time()-t0:.0f}s) — {len(research['deep_dive'])} chars")

    ctx2 = f"[RSI] Round 2 — Critique & Refine\nTask: {question}\n\n"
    for role in ("critical", "deep_dive"):
        ctx2 += f"\n{role.upper()} said:\n{research[role][:4000]}\n"

    print(f"  RSI refine ({W12})... ", end="", flush=True)
    t0 = time.time()
    research["refine"] = await call_model(
        W12,
        [{"role": "user", "content": ctx2 + "\n\nRefine the two analyses — identify gaps, add missing techniques, produce a sharper plan."}],
        max_tokens=8192, temperature=0.3)
    print(f"done ({time.time()-t0:.0f}s) — {len(research['refine'])} chars")

    ctx3 = ctx2 + f"\nREFINE said:\n{research['refine'][:4000]}\n"
    print(f"  RSI synthesis ({GLM52})... ", end="", flush=True)
    t0 = time.time()
    unified = await conductor_call(
        GLM52,
        ctx3 + "\n\nSynthesize all three analyses into ONE complete, rigorous exploitation plan with specific steps, CVEs, and payloads.",
        category="attack_planning",
        max_tokens=8192, temperature=0.3)
    print(f"done ({time.time()-t0:.0f}s) — {len(unified)} chars")

    return {"research": research, "unified_plan": unified}

async def main():
    with open("deep_research_osmania_exploits.json") as f:
        dr_data = json.load(f)

    debate_question = (
        "Given the following deep research on a university infrastructure:\n\n"
        f"{dr_data.get('final', '')[:5000]}\n\n"
        "---\n\n"
        "Your task: Present your exploitation strategy for this target's heterogeneous "
        "technology stack (Apache 2.2.15, Tomcat 9/Ghostcat, Oracle 19c, MSSQL, PHP 5.6, "
        "ModSecurity WAF). Include specific CVE mappings, chaining order, WAF bypass "
        "techniques, and post-exploitation steps."
    )

    print("=" * 70)
    print("ROUND 1: Initial Positions")
    print("=" * 70)
    positions = {}
    for key in DEBATE_MODELS:
        print(f"\n  {key} stating position... ", end="", flush=True)
        t0 = time.time()
        pos = await debate(key, debate_question, temperature=0.85)
        print(f"done ({time.time()-t0:.0f}s) — {len(pos)} chars")
        positions[key] = pos

    print("\n" + "=" * 70)
    print("ROUND 2: Cross-Critique")
    print("=" * 70)
    critiques = {}
    for key in DEBATE_MODELS:
        others = {k: (v[:2500]) for k, v in positions.items() if k != key}
        others_text = "\n\n".join(f"<{k}>:\n{v}" for k, v in others.items())
        my_pos = positions[key][:2000] if len(positions[key]) > 2000 else positions[key]
        critique_prompt = (
            f"Debate positions from other models:\n\n{others_text}\n\n"
            f"Your position was:\n{my_pos}\n\n"
            f"Critique the other models' positions. Identify flaws, missing techniques, "
            f"impractical steps, or incorrect assumptions. Then defend and improve your own "
            f"position by incorporating the strongest points from any model."
        )
        print(f"  {key} critiquing... ", end="", flush=True)
        t0 = time.time()
        crit = await debate(key, critique_prompt, temperature=0.8)
        print(f"done ({time.time()-t0:.0f}s) — {len(crit)} chars")
        critiques[key] = crit

    print("\n" + "=" * 70)
    print("ROUND 3: Consensus Synthesis (glm-5.2)")
    print("=" * 70)
    all_text = "\n\n".join(
        f"=== {key} ===\nINITIAL:\n{positions[key][:2000]}\n\nCRITIQUE:\n{critiques[key][:2000]}"
        for key in DEBATE_MODELS
    )
    synthesis_prompt = (
        f"Below are 4 model debates on exploiting a university infrastructure.\n\n"
        f"{all_text}\n\n"
        f"---\n\n"
        f"Synthesize a SINGLE definitive exploitation plan that merges the strongest "
        f"elements from all 4 models. For every technique, state which model contributed it. "
        f"The plan must include: entry vector, chaining order, WAF bypass strategy, "
        f"post-exploitation, and a timeline in hours. Be specific — CVEs, payloads, tools."
    )
    print(f"  glm-5.2 (synthesis)... ", end="", flush=True)
    t0 = time.time()
    synthesis = await conductor_call(
        GLM52, synthesis_prompt, category="attack_planning",
        max_tokens=8192, temperature=0.3)
    print(f"done ({time.time()-t0:.0f}s) — {len(synthesis)} chars")

    print("\n" + "=" * 70)
    print("PHASE 2: RSI — Final Refined Plan")
    print("=" * 70)
    rsi_input = f"Debate synthesis:\n{synthesis[:5000]}\n\n---\n\n{synthesis_prompt}"
    rsi_result = await rsi_phase(rsi_input)

    output = {
        "debate_positions": {k: v for k, v in positions.items()},
        "debate_critiques": {k: v for k, v in critiques.items()},
        "debate_synthesis": synthesis,
        "rsi_research":     {k: v for k, v in rsi_result["research"].items()},
        "rsi_final_plan":   rsi_result["unified_plan"],
    }

    with open("debate_rsi_final_plan_full.json", "w") as f:
        json.dump(output, f, indent=2)
    with open("debate_rsi_final_plan.md", "w") as f:
        f.write("# Debate -> RSI Final Exploitation Plan\n\n")
        f.write("## Models\n")
        f.write("- glm-5.2 (synthesis, via conductor)\n")
        f.write("- worm-12\n- worm-13\n- worm-480b\n")
        f.write("- nemotron-super (RSI critical)\n- mistral-large (RSI deep dive)\n\n")
        f.write("## 1. Debate Synthesis\n\n")
        f.write(synthesis)
        f.write("\n\n---\n\n")
        f.write("## 2. RSI Research Outputs\n\n")
        for role, text in rsi_result["research"].items():
            f.write(f"### {role.upper()}\n\n{text}\n\n")
        f.write("---\n\n")
        f.write("## 3. RSI Final Plan\n\n")
        f.write(rsi_result["unified_plan"])

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for key in DEBATE_MODELS:
        print(f"  {key}: pos={len(positions[key])} chars, crit={len(critiques[key])} chars")
    print(f"  synthesis: {len(synthesis)} chars")
    for role, text in rsi_result["research"].items():
        print(f"  RSI {role}: {len(text)} chars")
    print(f"  RSI final: {len(rsi_result['unified_plan'])} chars")
    print(f"\nSaved: debate_rsi_final_plan.md, debate_rsi_final_plan_full.json")

if __name__ == "__main__":
    asyncio.run(main())
