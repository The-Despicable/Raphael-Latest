"""
Re-run only gemma4 reasoning + merge steps with improved refusal detection.
Uses existing nemotron critical + worm-12 offensive output.
"""
import asyncio, json, sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from orchestrator.conductor import conductor_call

GEMMA4 = "bjoernb/gemma4-31b-think:latest"

async def main():
    data = json.load(open("debate_rsi_final_plan_full.json"))
    rsi = data.get("rsi_phases", {})
    synthesis = data["debate_synthesis"]
    critical = rsi.get("rsi_critical", "")

    base = f"[RSI] Final Exploitation Plan\n\nDebate Synthesis:\n{synthesis[:5000]}\n\n"

    print("  gemma4 (refined reasoning plan)... ", end="", flush=True)
    t0 = time.time()
    gemma_plan = await conductor_call(GEMMA4,
        f"{base}\n\nCritical Analysis:\n{critical[:3000]}\n\n"
        "Produce the definitive exploitation plan. Include: entry vectors, WAF bypass techniques (SQLi obfuscation, chunked transfer, HTTP param pollution), "
        "chaining order (Apache → Tomcat/Ghostcat → Oracle/MSSQL), post-exploitation (credential harvesting, lateral movement, persistence). "
        "Be specific with CVEs, payloads, and tool commands. Structure by phase with estimated timeline.",
        category="attack_planning",
        max_tokens=8192, temperature=0.4)
    print(f"done ({time.time()-t0:.0f}s) — {len(gemma_plan)} chars")

    worm_pass = rsi.get("rsi_worm_offensive_pass", "")

    print("  gemma4 (final merge)... ", end="", flush=True)
    t0 = time.time()
    final = await conductor_call(GEMMA4,
        f"Below are two analyses of the same target:\n\n"
        f"=== GEMMA4 (reasoned plan) ===\n{gemma_plan[:3000]}\n\n"
        f"=== WORM-12 (offensive specifics) ===\n{worm_pass[:5000]}\n\n"
        "Merge them into ONE final exploitation plan. Keep the reasoned structure from gemma4 "
        "and embed the offensive specifics from worm-12 into each section. The result must be "
        "a complete, executable document.",
        category="attack_planning",
        max_tokens=8192, temperature=0.3)
    print(f"done ({time.time()-t0:.0f}s) — {len(final)} chars")

    rsi["rsi_gemma_plan"] = gemma_plan
    rsi["rsi_final_merge"] = final
    data["rsi_phases"] = rsi

    with open("debate_rsi_final_plan_full.json", "w") as f:
        json.dump(data, f, indent=2)
    with open("debate_rsi_final_plan.md", "w") as f:
        f.write("# Debate → RSI Final Exploitation Plan\n\n")
        f.write("## Pipeline\n")
        f.write("1. Round 1-2: 4-model debate (gemma4, worm-12/13/480b)\n")
        f.write("2. Round 3: gemma4 synthesis\n")
        f.write("3. RSI critical: nemotron-super\n")
        f.write("4. Reasoning plan: gemma4\n")
        f.write("5. Offensive pass: worm-12\n")
        f.write("6. Final merge: gemma4\n\n---\n\n")
        f.write("## Round 3: Debate Synthesis\n\n")
        f.write(synthesis + "\n\n---\n\n")
        f.write("## RSI: Critical Analysis (nemotron-super)\n\n")
        f.write(critical + "\n\n---\n\n")
        f.write("## RSI: Reasoning Plan (gemma4)\n\n")
        f.write(gemma_plan + "\n\n---\n\n")
        f.write("## RSI: Offensive Pass (worm-12)\n\n")
        f.write(worm_pass + "\n\n---\n\n")
        f.write("## RSI: Final Merged Plan\n\n")
        f.write(final)

    print(f"\ngemma4 plan: {len(gemma_plan)} chars")
    print(f"gemma4 merge: {len(final)} chars")
    print("Saved.")

asyncio.run(main())
