from ..providers import call_model

RSI_TEAM = {
    "critical":  "nemotron-super",   # rigorous logical analysis, catch flaws
    "deep_dive": "mistral-large",     # technical depth, step-by-step verification
    "synthesis": "kimi",              # integrate findings, final proof
}

async def handle(question, rounds=2, temperature=0.5):
    """
    RSI (Research, Search, Integrate) mode.
    nemotron-super (critical analysis) + mistral-large (deep dive) + kimi (synthesis).
    """
    ctx = f"[RSI] Research, Search, Integrate\nTask: {question}\n\n"
    ctx += "Phase 1 (Research): Analyze the problem rigorously."
    ctx += "\nPhase 2 (Search): Verify assumptions, check edge cases."
    ctx += "\nPhase 3 (Integrate): Produce a complete, proven answer."

    research = {}
    for role, alias in RSI_TEAM.items():
        research[role] = await call_model(
            alias,
            [{"role": "user", "content": f"[{role.upper()}]\n{ctx}"}],
            max_tokens=4096, temperature=temperature
        )

    ctx2 = f"[RSI] Round 2 — Critique & Refine\nTask: {question}\n\n"
    for role, text in research.items():
        ctx2 += f"\n{role.upper()} said:\n{text}\n"

    unified = await call_model(
        RSI_TEAM["synthesis"],
        [{"role": "user", "content": ctx2 + "\nSynthesize the three analyses into ONE complete, rigorous solution with proof."}],
        max_tokens=4096, temperature=0.3
    )

    return {"research": research, "unified_plan": unified}
