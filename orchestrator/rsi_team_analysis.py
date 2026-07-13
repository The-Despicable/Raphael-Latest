#!/usr/bin/env python3
"""RSI-style team analysis: 4 models + synthesis.
Each model independently analyzes Claude patterns for Raphael, then kimi-k2.6 synthesizes."""

import asyncio, json, time, sys, os
from orchestrator.providers import call_model

TEAM = {
    "deepseek-v4-flash": "oc-deepseek",
    "glm-5.1": "oc-hy3-free",
    "kimi-k2.6": "oc-kimi",
    "nemotron-ultra": "oc-nemotron-ultra",
}

TASK = """You are analyzing Claude Code's architecture for porting to Raphael 2.0, a working autonomous security platform.

RAPHAEL 2.0:
- 6 microservices: cai-service, cloak-service, mhddos-service, c2-server, phishing, recon-pipeline
- SWORD pipeline: recon -> scan -> exploit -> postex -> exfil -> phish
- Adaptive brain: Thompson sampling, UCB, PSO for model/tool selection
- Proxy guard: Tor + WireGuard + FlareTunnel + jitter + DNS leak prevention
- MCP Hub with 12 tools across 7 categories
- ~7900 lines Python, real binaries (nmap, sqlmap, nuclei, hydra, metasploit)
- No tests (except MCP hub), no session persistence, basic retry, brain resets between engagements

CLAUDE PATTERNS EVALUATED:
1. Undercover - strip AI attribution markers from LLM-generated text (em-dash, "As an AI", "delve", "robust", sentence length variance)
2. autoDream - cross-session memory consolidation with SQLite for Thompson priors
3. Hook system - 25+ lifecycle events (engagement.started, recon.port_open, brain.arm_pulled, exfil.transmitted)
4. Retry - exponential backoff + jitter + model fallback on 529 rate limits
5. Session fork/resume - checkpoint and branch
6. CLAUDE.md hierarchy - global/project/private context files
7. Permission system - 5-level cascade (bypass, allow, auto, classifier, deny)
8. Subagent model - fork (shared cache), teammate (tmux), worktree (isolated branch)
9. 5-tier compaction - context window management
10. KAIROS perpetual daemon

PREVIOUS ANALYSIS (minimax-m3 & kimi-k2.6 both agreed):
- Undercover: HIGH value (~120-150 lines) — strips attribution from phishing/exfil content
- Hook system: MEDIUM-HIGH value (~350 lines) — formalizes ad-hoc events in recon-pipeline
- Retry: MEDIUM value (~80-180 lines) — cheap reliability improvement
- autoDream: DISPUTED — minimax said YES (8/10), kimi said NO (4/10, opsec risk)
- Everything else: LOW value — either violates opsec model or doesn't fit

YOUR JOB: Provide FRESH critical analysis. Don't just repeat prior findings. Consider:
1. Is the prior minimax-m3 analysis too optimistic about autoDream? (kimi said state.json reset is intentional anti-forensics)
2. Are any of the "low value" patterns actually worth porting for a specific reason minimax/kimi missed?
3. What's the actual implementation cost in raphael-2.0 file paths?
4. What order should they be implemented?

Be specific, reference actual raphael-2.0/orchestrator/ files, and give SCORE 1-10 for each pattern."""

SYNTHESIS_TASK = """You are the lead architect synthesizing a team's analysis.

TEAM MEMBER ANALYSES:

{d}

YOUR JOB: Produce the FINAL ANSWER. Include:
1. A table of all 10 patterns with final score (1-10), effort estimate, and verdict (PORT / SKIP / DEFER)
2. Ranked implementation priority order with exact file paths
3. Any pattern the team disagreed on — state YOUR final call and why
4. Estimated total lines of code to implement everything worth porting

Be decisive. One unified recommendation. No hedging."""

async def main():
    print("=" * 70)
    print("RSI TEAM ANALYSIS: Claude Patterns × Raphael 2.0")
    print(f"Team: {', '.join(TEAM.keys())}")
    print("=" * 70 + "\n")

    all_results = {}

    # Phase 1: All 4 models analyze independently in parallel
    print("▶ Phase 1: Independent Analysis (4 models in parallel)\n")

    async def analyze_one(name):
        t0 = time.time()
        result = await call_model(TEAM[name], [{"role": "user", "content": TASK}], temperature=0.4)
        elapsed = time.time() - t0
        print(f"  {name} done ({elapsed:.0f}s)")
        return name, result

    tasks = [analyze_one(name) for name in TEAM]
    done = await asyncio.gather(*tasks)

    for name, result in done:
        all_results[name] = result
        preview = result[:80].replace("\n", " ")
        print(f"\n  --- {name} (preview) ---")
        print(f"  {preview}...")

    print("\n" + "=" * 70)
    print("▶ Phase 2: Cross-Critique (each model reads all others)\n")

    critique_text = ""
    for name, text in all_results.items():
        critique_text += f"\n=== {name} ===\n{text}\n"

    # Phase 2: All 4 models critique each other
    critique_prompt = f"""Read all 4 analyses below. Then give a CRITIQUE:

1. Which analysis is most accurate? Which is wrong?
2. Where do they agree? Where do they disagree?
3. What did each model miss?
4. Give your UPDATED scores (1-10) for each of the 10 patterns after reading the others.

{critique_text}
"""

    async def critique_one(name):
        t0 = time.time()
        result = await call_model(TEAM[name], [{"role": "user", "content": critique_prompt}], temperature=0.3)
        elapsed = time.time() - t0
        print(f"  {name} critique done ({elapsed:.0f}s)")
        return name, result

    critiques = await asyncio.gather(*[critique_one(name) for name in TEAM])
    critique_text_full = ""
    for name, text in critiques:
        all_results[f"{name}_critique"] = text
        critique_text_full += f"\n=== {name} CRITIQUE ===\n{text}\n"

    print("\n" + "=" * 70)
    print("▶ Phase 3: Final Synthesis (kimi-k2.6 produces final report)\n")

    synthesis_input = ""
    for name, text in all_results.items():
        synthesis_input += f"\n=== {name} ===\n{text}\n"

    final = await call_model(
        TEAM["kimi-k2.6"],
        [{"role": "user", "content": SYNTHESIS_TASK.format(d=synthesis_input)}],
        temperature=0.2,
        max_tokens=4096
    )

    print(final)
    print("\n" + "=" * 70)
    print("SAVING REPORT...")

    report = {
        "task": "Claude Patterns × Raphael 2.0 RSI Analysis",
        "team": {k: v for k, v in TEAM.items()},
        "phase1_individual": {k: all_results[k] for k in TEAM},
        "phase2_critiques": {k: all_results[f"{k}_critique"] for k in TEAM if f"{k}_critique" in all_results},
        "phase3_synthesis": final,
    }

    with open("rsi_team_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("Saved to rsi_team_report.json")
    
    with open("rsi_team_report_final.md", "w") as f:
        f.write(final)
    print("Saved to rsi_team_report_final.md")

asyncio.run(main())
