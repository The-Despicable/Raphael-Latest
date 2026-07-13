#!/usr/bin/env python3
"""Run deep research on all 4 topics in parallel, then synthesize with kimi + gemma4."""
import asyncio, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config.paths import get_base_dir

from orchestrator.modes.deep_research import handle as deep_research
from orchestrator.providers import call_model

TOPICS = {
    "waf_bypass": "WAF bypass techniques — current state of ModSecurity CRS bypasses, Oracle vs MySQL specific payload research, and evasion techniques for 2024-2026",
    "attack_graph": "Attack graph models — how frameworks like CALDERA, MITRE ATT&CK Navigator, and BloodHound model attack paths, to validate our Raphael 2.0 TargetState design using NetworkX",
    "proxy_opsec": "Proxy chaining and OPSEC — current best practices for multi-hop proxy chains, Tor vs VPN tradeoffs, academic proxy compromises, and operational security for offensive security engagements",
    "llm_exploit_gen": "LLM-based exploit generation — what the research literature says about reliability, hallucination rates, code quality, and safety of using LLMs to generate offensive security payloads",
}

async def run_one_topic(name: str, question: str) -> dict:
    print(f"\n{'='*60}")
    print(f"STARTING: {name}")
    print(f"{'='*60}")
    t0 = time.time()
    try:
        result = await deep_research(question, temperature=0.5)
        elapsed = time.time() - t0
        print(f"DONE {name} ({elapsed:.0f}s): {result.get('sources_found', 0)} sources, {result.get('queries_run', 0)} queries")
        return {"topic": name, "question": question, "result": result, "elapsed": elapsed, "error": None}
    except Exception as e:
        elapsed = time.time() - t0
        print(f"FAILED {name} ({elapsed:.0f}s): {e}")
        return {"topic": name, "question": question, "result": None, "elapsed": elapsed, "error": str(e)}

async def main():
    print("=" * 70)
    print("DEEP RESEARCH: 4 Topics in Parallel")
    print("=" * 70)

    # Run all 4 topics concurrently
    tasks = [run_one_topic(name, q) for name, q in TOPICS.items()]
    results = await asyncio.gather(*tasks)

    print(f"\n\n{'='*70}")
    print("ALL 4 COMPLETE — Synthesizing with kimi + gemma4")
    print(f"{'='*70}")

    # Build consolidated research text
    consolidated = ""
    for r in results:
        topic = r["topic"]
        if r["result"] and r["result"].get("final"):
            text = r["result"]["final"]
        else:
            text = f"[ERROR: {r['error']}]"
        consolidated += f"\n\n---\n# TOPIC: {topic}\n{text[:6000]}\n"

    # Save raw results
    report = {
        "individual": results,
        "timestamp": time.time(),
    }
    out_path = get_base_dir() / "deep_research_4topics_raw.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nRaw results saved to {out_path}")

    # Phase 2: kimi + gemma4 synthesis
    print("\n▶ Synthesizing with kimi...")
    kimi_prompt = f"""You are synthesizing 4 deep research investigations into a unified report.

{consolidated}

Produce a unified synthesis organized by theme. For each topic:
1. Key findings (what's established)
2. Contradictions or disagreements found
3. Implications for Raphael 2.0 (an autonomous offensive security framework)
4. Open questions

Then provide a cross-cutting analysis:
- Common patterns across all 4 topics
- What's mature vs what's evolving
- Priority recommendations for implementation

Output in markdown with clear sections."""
    kimi_synthesis = await call_model("kimi", [{"role": "user", "content": kimi_prompt}], max_tokens=8192, temperature=0.3)
    
    print("\n▶ Synthesizing with gemma4...")
    gemma4_prompt = f"""You are providing a critical second opinion on the same research.

{consolidated}

Review the findings. What did kimi miss? What would you emphasize differently?
Provide your own synthesis covering the same 4 topics. Be specific about:
- Where you agree
- Where you disagree
- What should be prioritized for Raphael 2.0
- What risks or pitfalls the research reveals

Output in markdown."""
    gemma4_synthesis = await call_model("gemma4", [{"role": "user", "content": gemma4_prompt}], max_tokens=4096, temperature=0.4)

    # Phase 3: Final merged report
    print("\n▶ Final merge...")
    merge_prompt = f"""Two models analyzed the same 4-topic deep research. Merge their analyses into a single decisive report.

=== KIMI SYNTHESIS ===
{kimi_synthesis[:6000]}

=== GEMMA4 ANALYSIS ===
{gemma4_synthesis[:6000]}

Produce a merged report that:
1. Keeps what both agree on
2. Flags where they disagree and why
3. Adds YOUR judgment as the arbitrator
4. Ends with concrete action items for Raphael 2.0

Output in markdown."""
    final_merge = await call_model("kimi", [{"role": "user", "content": merge_prompt}], max_tokens=8192, temperature=0.3)
    if not final_merge or final_merge.startswith("[ERROR") or final_merge.startswith("[TIMEOUT"):
        final_merge = await call_model("mistral-large", [{"role": "user", "content": merge_prompt}], max_tokens=8192, temperature=0.3)

    # Final report
    final_report = f"""# Raphael 2.0 — Deep Research: 4 Topics

## Individual Research Reports

""" + "\n".join(f"### {r['topic']}\n{chr(10).join(r['result']['final'].split(chr(10))[:50]) if r['result'] else 'ERROR'}\n" for r in results) + f"""

---

## Kimi Synthesis

{kimi_synthesis}

---

## Gemma4 Second Opinion

{gemma4_synthesis}

---

## Merged Final Verdict

{final_merge}

---

*Generated {time.ctime()} | {len(results)} topics, {sum(r.get('elapsed', 0) for r in results):.0f}s total research time*"""

    final_path = get_base_dir() / "deep_research_4topics_final.md"
    final_path.write_text(final_report)
    print(f"\nFinal report saved to {final_path}")

    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    for r in results:
        status = "✓" if r["result"] else "✗"
        sources = r["result"].get("sources_found", 0) if r["result"] else 0
        queries = r["result"].get("queries_run", 0) if r["result"] else 0
        print(f"  {status} {r['topic']}: {sources} sources, {queries} queries, {r['elapsed']:.0f}s")
    print(f"\nKimi synthesis: {len(str(kimi_synthesis))} chars")
    print(f"Gemma4 synthesis: {len(str(gemma4_synthesis))} chars")

if __name__ == "__main__":
    asyncio.run(main())
