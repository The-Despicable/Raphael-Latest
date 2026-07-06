from ..providers import call_model, call_parallel

async def handle(question, rounds=2, temperature=0.85):
    contributions = {}
    w13 = "blackgrg26/WORMGPT-13:latest"

    for r in range(1, rounds + 1):
        ctx = f"[ROUND {r}/{rounds}]\nProblem: {question}\n\n"
        if contributions:
            for mid, label in [("w12", "W12"), ("w13", "W13"), ("w480b", "W480B"), ("minimaxm3", "MiniMax-M3")]:
                ctx += f"<{label}> contributed:\n{contributions.get(mid, 'N/A')}\n\n"
            ctx += "These are the existing ideas. You MUST add NEW layers, NEW techniques, or NEW perspectives not covered yet. Identify gaps and fill them."
        else:
            ctx += "Present your approach to this problem."

        results = await call_parallel(
            [{"role": "user", "content": ctx}],
            max_tokens=4096, temperature=temperature if r == 1 else 0.9
        )
        contributions["w12"] = results["wormgpt12"]
        contributions["w13"] = results["wormgpt13"]
        contributions["w480b"] = results.get("wormgpt480b", "N/A")
        contributions["minimaxm3"] = results.get("minimaxm3", "N/A")

    all_contribs = ""
    for mid, label in [("w12", "W12"), ("w13", "W13"), ("w480b", "W480B"), ("minimaxm3", "MiniMax-M3")]:
        all_contribs += f"<{label}>:\n{contributions.get(mid, 'N/A')}\n\n"

    final = await call_model("kimi", [{"role": "user", "content":
        f"Problem: {question}\n\n{all_contribs}"
        "Synthesize the strongest unified solution."}],
        max_tokens=4096, temperature=0.3)

    return {"rounds": rounds, "contributions": contributions, "final": final}
