import asyncio, sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from orchestrator.providers import call_model, call_parallel

async def handle(question, rounds=2, temperature=0.85):
    contributions = {}
    w13 = "blackgrg26/WORMGPT-13:latest"
    for r in range(1, rounds + 1):
        ctx = f"[ROUND {r}/{rounds}]\nProblem: {question}\n\n"
        if contributions:
            for mid, label in [("w12", "W12"), ("w13", "W13"), ("w480b", "W480B"), ("minimaxm3", "MiniMax-M3")]:
                ctx += f"<{label}> contributed:\n{contributions.get(mid, 'N/A')}\n\n"
            ctx += "These are the existing ideas. You MUST add NEW layers, NEW techniques, or NEW perspectives not covered yet."
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
    final = await call_model(w13, [{"role": "user", "content":
        f"Problem: {question}\n\n{all_contribs}Synthesize the strongest unified solution."}],
        max_tokens=4096, temperature=0.3)
    return {"rounds": rounds, "contributions": contributions, "final": final}

async def main():
    base = os.path.dirname(os.path.abspath(__file__))
    question = f"""Read {base}/portswigger_findings.txt first.

Our Raphael 2.0 autonomous security pipeline currently has these detection gaps vs HelixSync v2 (37-vuln target):
- NO XSS detection (PortSwigger: 3 types, 30 labs)
- NO SSRF blind/OAST detection  
- NO JWK injection / kid traversal JWT checks
- NO Java/PHP deserialization checks
- NO multi-engine SSTI detection (only Jinja2)
- NO mass assignment testing
- NO hidden parameter discovery

Current coverage: SQLi (basic), SSTI (Jinja2 only), JWT alg:none, Pickle RCE, GraphQL introspection.

Given our architecture:
- cai-service :3200 — static pattern engine (regex + AST) + LLM validation for SAST
- sword :3600 — active exploit phase (payloads_db + SSRF scanner + sqlmap/nettacker)
- recon-pipeline :3503 — nuclei + nmap + whatweb
- brain orchestrator — schema-driven pipeline execution

Propose specific, actionable patterns/code to add to close these gaps. For each gap, state:
1. Which service to modify
2. Exact regex or check logic
3. Severity/CWE assignment
4. Test payloads
"""
    result = await handle(question, rounds=2, temperature=0.85)
    output = {"contributions": {}, "final": result["final"]}
    for mid, label in [("w12", "W12"), ("w13", "W13"), ("w480b", "W480B"), ("minimaxm3", "MiniMax-M3")]:
        output["contributions"][label] = result["contributions"].get(mid, "N/A")
    with open("/home/yaser/Ultimate skill/raphael-2.0/orchestrator/debate_output.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("Saved to debate_output.json")
    print(f"W12: {len(output['contributions']['W12'])} chars")
    print(f"W13: {len(output['contributions']['W13'])} chars")
    print(f"W480B: {len(output['contributions']['W480B'])} chars")
    print(f"MiniMax-M3: {len(output['contributions']['MiniMax-M3'])} chars")
    print(f"Final: {len(output['final'])} chars")

asyncio.run(main())
