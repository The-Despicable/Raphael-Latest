#!/usr/bin/env python3
"""RSI analysis: port RedTeamAgent patterns into Raphael 2.0.
4-model team with cross-critique and synthesis."""

import asyncio, json, httpx, time, sys, os

API_BASE = "https://integrate.api.nvidia.com/v1"
API_KEY = os.getenv("NVIDIA_API_KEY")
if not API_KEY:
    raise RuntimeError("NVIDIA_API_KEY environment variable required")

TEAM = {
    "kimi-k2.6": "moonshotai/kimi-k2.6",
    "nemotron-ultra-550b": "nvidia/nemotron-3-ultra-550b-a55b",
}

TASK = """You are analyzing RedTeamAgent (https://github.com/NeoTheCapt/RedteamAgent) for porting its best features into Raphael 2.0, an autonomous security platform.

RAPHAEL 2.0 (existing):
- 10 Docker microservices: cai-service :3200, mhddos :3300, cloak :3400, c2-server :3501, phishing :3502, recon-pipeline :3503, sword :3600, brain :3700, mcp-hub :3500, tor-proxy
- 6-phase Sword pipeline: recon -> scan -> exploit -> postex -> exfil -> phish
- 8 CAI agents: recon, scan, exploit, defend, forensic, oracle, chat, audit
- Multi-provider LLM routing (FreeLLM/Groq/NVIDIA/Ollama chain)
- OpSec: Tor + Cloudflare + SSH multi-hop, kill switches, encrypted state
- ~7900 lines Python, real binaries (nmap, sqlmap, nuclei, hydra, metasploit)
- No case collection pipeline, no structured resume, no reference library

REDTEAMAGENT FEATURES TO EVALUATE FOR PORTING:

1. CASE COLLECTION PIPELINE (cases.db)
   - SQLite schema: cases(id, method, url, url_path, params_key_sig UNIQUE, type, source, status, stage)
   - 4 producers: mitmproxy (live traffic), Katana (crawler), recon_ingest (stdin), spec_ingest (OpenAPI)
   - type classification: api, form, graphql, upload, websocket, javascript, page, stylesheet, data, unknown
   - Parameter extraction: query, body, path params with dedup signature (MD5 of origin|sorted_keys|control_values)
   - Priority scoring: source weight (exploit-dev=500, katana-xhr=460) + method bonus (POST=180) + path pattern bonus
   - Dispatcher: zero-token fetch/done/error/set-stage/reset-stale operations
   - Stage state machine: ingested -> source_analyzed -> api_tested -> vuln_confirmed -> fuzz_pending -> exploited -> clean/errored

2. RESUME / STALL RECOVERY
   - /resume command: resolve_engagement_dir() -> read scope.json/findings/queue -> reset-stale 10min -> restart producers -> resume dispatch
   - dispatcher reset-stale: recovers stuck 'processing' cases back to 'pending'
   - Auth respawn check: detects new credentials, triggers re-recon
   - Intel changed check: detects new intel.md entries, triggers osint-analyst
   - In-flight guard: prevents double-dispatch for same (agent, type, stage)
   - Stop protocol: check stats-by-stage, active stages, processing rows, collection health, surface coverage

3. REFERENCE LIBRARY
   - references/INDEX.md with categorized entries per agent role
   - vuln-checklists/ (10 OWASP Top 10:2025 files)
   - api-security/ (10 API Security Top 10:2023 files)
   - offensive-tactics/ (20+ TTP files: initial-access, credential-access, lateral-movement, persistence, privesc, defense-evasion)
   - active-directory/ (4 files: kerberos, enumeration, persistence, ADCS)
   - payloads/ (20 files: SQLi, XSS, SSTI, CSRF, etc.)
   - tools/ cheatsheets (recon, fuzzing, exploitation, cracking)
   - Agents load only what they need on demand

4. ENGAGEMENT MODE SPLIT
   - /engage: interactive, asks auth setup (proxy/cookie/header/skip), asks phase approval, parallel by default
   - /autoengage = /engage --auto: zero interaction, auto-skip auth, auto-register if endpoint found, auto-use discovered creds, never asks, logs errors and continues

5. PARTIAL REPORT SYNTHESIS
   - compose_partial_report.sh: zero-token interim report from existing artifacts WITHOUT LLM
   - Reads: scope.json (target/status/phase), findings.md (finding count + content), intel.md (content), cases.db (pipeline stage tally)
   - Triggered: after every 5 findings, at any controlled stop
   - Produces: report.md with metadata, findings verbatim, intel verbatim, pipeline stats
   - finalize_engagement.sh: CTF recall closure gate, updates scope.json/log.md/report.md status, cleans WAL

YOUR JOB: For EACH of the 5 features above, provide:
- SCORE (1-10) for how valuable it is to port to Raphael 2.0
- Estimated implementation effort (LOC + files)
- Specific raphael-2.0 file paths where it should integrate
- What would need to change in Raphael 2.0 to support it
- Any opsec/architecture conflicts

Be specific. Reference actual file paths from both projects. Give implementation order."""

SYNTHESIS_TASK = """You are the lead architect synthesizing a team's analysis of what to port from RedTeamAgent into Raphael 2.0.

TEAM MEMBER ANALYSES:

{d}

YOUR JOB: Produce the FINAL PORTING PLAN. Include:
1. A table of all 5 features with final score (1-10), effort estimate, verdict (PORT / SKIP / DEFER)
2. Ranked implementation priority order with exact file paths for each
3. Where the team disagreed — state YOUR final call and why
4. Estimated total LOC to implement everything
5. Integration notes per feature (which raphael-2.0 services to modify)

Be decisive. One unified recommendation. No hedging."""

async def call_model(model_id, prompt, temperature=0.3, max_tokens=4096):
    async with httpx.AsyncClient(timeout=600) as cl:
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

async def safe_call(name, model_id, prompt, temperature=0.3, max_tokens=2048):
    t0 = time.time()
    print(f"  Starting {name}...", flush=True)
    try:
        result = await call_model(model_id, prompt, temperature, max_tokens)
        elapsed = time.time() - t0
        print(f"  {name} done ({elapsed:.0f}s) {len(result)} chars", flush=True)
        return name, result
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  {name} FAILED ({elapsed:.0f}s): {type(e).__name__}", flush=True)
        return name, f"[ERROR: {type(e).__name__}: {e}]"

async def main():
    print("=" * 70)
    print("RSI ANALYSIS: RedTeamAgent Patterns × Raphael 2.0")
    print(f"Team: {', '.join(TEAM.keys())}")
    print("=" * 70 + "\n")

    all_results = {}

    print("▶ Phase 1: Independent Analysis (models in parallel)\n", flush=True)
    tasks = [safe_call(name, TEAM[name], TASK, temperature=0.4) for name in TEAM]
    done = await asyncio.gather(*tasks)

    for name, result in done:
        all_results[name] = result
        preview = result[:120].replace("\n", " ")
        print(f"\n  --- {name} (preview) ---", flush=True)
        print(f"  {preview}...", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("▶ Phase 2: Cross-Critique (each model reads all others)\n", flush=True)

    critique_text = ""
    for name, text in all_results.items():
        critique_text += f"\n=== {name} ===\n{text}\n"

    critique_prompt = f"""Read all 4 analyses below. Then give a CRITIQUE:

1. Which analysis is most accurate? Which is wrong?
2. Where do they agree? Where do they disagree?
3. What did each model miss?
4. Give your UPDATED scores (1-10) for each of the 5 features after reading the others.

{critique_text}
"""

    critique_tasks = [safe_call(f"{name}_critique", TEAM[name], critique_prompt, temperature=0.3) for name in TEAM]
    critiques = await asyncio.gather(*critique_tasks)
    for name, text in critiques:
        all_results[name] = text

    print("\n" + "=" * 70, flush=True)
    print("▶ Phase 3: Final Synthesis (kimi-k2.6 produces final porting plan)\n", flush=True)

    synthesis_input = ""
    for name, text in all_results.items():
        synthesis_input += f"\n=== {name} ===\n{text}\n"

    _, final = await safe_call(
        "kimi-synthesis", TEAM["kimi-k2.6"],
        SYNTHESIS_TASK.format(d=synthesis_input),
        temperature=0.2, max_tokens=8192
    )

    print(final, flush=True)
    print("\n" + "=" * 70, flush=True)
    print("SAVING REPORT...", flush=True)

    out_dir = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(out_dir, "rsi_redteam_port_report.json")
    final_path = os.path.join(out_dir, "rsi_redteam_port_plan.md")

    report = {
        "task": "RedTeamAgent Patterns × Raphael 2.0 Porting Analysis",
        "team": {k: v for k, v in TEAM.items()},
        "phase1_individual": {k: all_results.get(k, "") for k in TEAM},
        "phase2_critiques": {k: all_results.get(f"{k}_critique", "") for k in TEAM},
        "phase3_synthesis": final,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved to {report_path}", flush=True)

    with open(final_path, "w") as f:
        f.write(final)
    print(f"Saved to {final_path}", flush=True)

    print("\nDONE. Open the plan file and start integrating.", flush=True)

asyncio.run(main())
