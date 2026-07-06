#!/usr/bin/env python3
"""
Use the reasoning team (nemotron-super, mistral-large, kimi, gemma4)
via conductor with sanitize_prompt for safety-filtered models.
Produces a prioritized fix plan for the 35+ security audit findings.
"""
import asyncio, json, sys, os, logging
sys.path.insert(0, '.')
logging.basicConfig(level=logging.INFO, format="%(message)s")

from orchestrator.conductor import conductor_call, conductor_call_parallel

AUDIT_SUMMARY = """
Raphael 2.0 — Security Audit Findings (35+ total)

CRITICAL (8):
C1: Live NVIDIA API key in .env — provides access to 12 paid models
C2: Live Telegram bot token in telegram mcp/.env
C3: shell=True command injection in telegram mcp/mcp_server.py:39-41
C4: Python code injection via f-string in spiderfoot_wrapper.py:53-105
C5: Zero forensic countermeasures despite "memory-only" claims
C6: Global TLS cert validation bypass in proxy_guard.py:222-223,467
C7: 9/10 Docker containers run as root with NET_RAW/NET_ADMIN
C8: Evidence of live attacks against real targets on disk

HIGH (12):
H1: Default/weak credentials throughout .env
H2: --no-anonymity flag bypasses all proxy enforcement
H3: OpSec bypass propagates silently through autonomous mode
H4: Hardcoded sudo password in setup_killswitch.sh
H5: Typo in kill_switch_disable.sh:21 (missing 'CEPT')
H6: No IPv6 isolation — zero ip6tables rules
H7: DNS leak in proxy_guard.py:697
H8: No API cost controls or usage tracking
H9: Safety-filter evasion via sanitize_prompt()
H10: Memory-only state claim unchecked (26 items)
H11: OpSec log stores exit IPs plaintext
H12: Real public IP on disk in /tmp/anonymity_test.log
"""

FIX_PROMPT = """You are a senior security engineer. Produce a concrete, actionable, prioritized fix plan for the Raphael 2.0 autonomous AI security platform.

Findings:
""" + AUDIT_SUMMARY + """

For EACH finding provide:
1. Exact file path and line(s) to modify
2. The precise code/config change (include actual code snippets)
3. Priority (Critical/High/Medium/Low)
4. Dependencies

Output as a numbered ordered list. Include actual Python code, Dockerfile directives, and config changes. No generic advice."""

DEEP_RESEARCH = """Deep research sourced: Docker rootless mode, command injection prevention (Semgrep/OpenStack), f-string injection mitigation, TLS cert validation (certifi), forensic countermeasures (tmpfs, mmap, shred), secrets management (Vault, Docker secrets)."""

async def main():
    print("=" * 60)
    print("Reasoning Team — Security Gap Analysis & Fix Plan")
    print("Models: nemotron-super + mistral-large + kimi + gemma4")
    print("=" * 60)

    prompt = DEEP_RESEARCH + "\n\n" + FIX_PROMPT

    # Phase 1: Run all 4 models in parallel via conductor (sanitizer for kimi, gemma4)
    print("\n[Phase 1] Reasoning team parallel analysis...", flush=True)
    results = await conductor_call_parallel(
        models=["nemotron-super", "mistral-large", "kimi", "gemma4"],
        prompt=prompt,
        category="strategic",
        max_tokens=8192,
        temperature=0.5,
        timeout=300,
        fallback_model="mistral-large",
    )

    for model, text in results.items():
        print(f"  {model}: {len(text)} chars", flush=True)

    # Phase 2: Kimi synthesizes all 4 into final plan (with sanitizer)
    print("\n[Phase 2] Kimi — Synthesis of all 4 analyses into final plan...", flush=True)
    combined = "\n\n=== NEXT ANALYSIS ===\n\n".join(
        f"<{m}>\n{t[:4000]}\n</{m}>" for m, t in results.items() if t and len(t) > 50
    )
    synthesis_prompt = f"""You are a senior security engineer producing the FINAL synthesized fix plan.

Below are 4 independent analyses of the same set of security vulnerabilities. Merge the best elements from each into one authoritative, prioritized fix plan.

{combined}

Output format: Numbered list ordered by priority (Critical first). Each entry must include: finding ID, exact file path, precise code/config change, priority, and verification step. Be extremely specific — include actual code and config."""
    
    final = await conductor_call(
        "kimi",
        synthesis_prompt,
        category="strategic",
        max_tokens=8192,
        temperature=0.3,
        timeout=300,
        fallback_model="mistral-large",
    )
    print(f"  Synthesis: {len(final)} chars", flush=True)

    # Save everything
    output = {**results, "kimi_synthesis": final}
    with open("reasoning_team_fixplan.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    with open("reasoning_team_final_plan.md", "w") as f:
        f.write("# Reasoning Team — Security Fix Plan\n\n")
        f.write("## Synthesized Final Plan\n\n")
        f.write(final or "No synthesis produced.")
        f.write("\n\n---\n\n## Individual Analyses\n\n")
        for m, t in results.items():
            f.write(f"### {m}\n\n{t[:5000]}\n\n---\n\n")

    print(f"\n{'='*60}")
    print("Done! Files saved:")
    print("  reasoning_team_fixplan.json (full JSON)")
    print("  reasoning_team_final_plan.md (readable report)")
    print(f"{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
