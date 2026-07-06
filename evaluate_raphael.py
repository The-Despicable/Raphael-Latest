#!/usr/bin/env python3
"""Evaluate Raphael 2.0 as a complete product — get Kimi and Gemma4 opinions."""
import asyncio, json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from orchestrator.providers import call_model

RAPHAEL_SUMMARY = """You are evaluating Raphael 2.0, an autonomous cybersecurity operations framework. Below is the complete architecture summary.

## Project Scope
18,707 lines of Python across 9 microservices, 58+ orchestrator modules, 8 CLI scripts, 8 shell scripts, 9 Dockerfiles, 2 docker-compose stacks.

## Architecture Layers

### Layer 1 — Proxy Enforcement (proxy_guard.py, 850 lines)
- Auto-detects proxy strategy: ProtonVPN → Tor → compromised-academic-infra chaining → direct (localhost)
- Circuit isolation: new Tor circuit per target domain
- Kill-switch: FAIL-DEAD mode aborts all connections on proxy failure
- Timing isolation: random 1-4s jitter between requests
- DNS leak prevention via SOCKS5h resolution

### Layer 2 — Multi-Provider LLM Orchestration (providers.py, 296 lines)
- 23 model aliases across 3 providers: NVIDIA API (kimi, mistral-large, nemotron), Ollama/Ollama API (gemma4, wormgpt variants), OmniRoute free fallbacks
- Prompt sanitization: strips target IPs/hostnames for safety-filtered models (kimi, gemma4) to prevent refusal
- PlanCache: TTL cache with hit/miss tracking, _plan_cache_clear() to prevent cache poisoning
- Retry with fallback chain: auto-falls through model list on failure

### Layer 3 — Adaptive Model Selection (adaptive_brain.py, 596 lines)
- Bayesian Thompson sampling + UCB bandit per context (sqli, xss, rce, recon, phishing, auth_jwt, persist, strategy, operations, proxy)
- Circuit breaker: 3 consecutive failures → 60s cooldown
- Domain shift detection: monitors success rate drift beyond 0.3 threshold
- PSO optimization, cache poisoning detection via output hash comparison
- SQLite-backed state persistence with decay half-life of 1 hour

### Layer 4 — Reasoning Teams (teams.py, 276 lines)
- 4 teams: reasoning, code-gen, offensive, planning
- 5 workflows: debate, analyze, code, execute, plan
- Debate workflow: 2 rounds with nemotron-super vs minimax, synthesis by kimi
- Execute workflow now supports waf_context and mimicry_profile parameters

### Layer 5 — Autonomous Engagement (modes/autonomous.py, 433 lines)
- 7-phase pipeline: recon → scan → exploit → postex → exfil → phish → cleanup
- Phase-specific prompts with MITRE ATT&CK technique injection
- Attack technique selector: maps recon output keywords to optimal techniques
- Ghost-in-the-Machine context injection for kernel-level ETW evasion
- Behavioral mimicry: temporal coherence (IST business hours), data velocity matching, process lineage mimicry
- Cleanup phase uses anti_forensics module directly (no LLM call)

### Core Security Modules

**Anti-Forensics** (anti_forensics.py, 286 lines): 5 platform-specific cleanup modules — CentOS/Apache (log injection, journal corruption, timestomping), Windows/IIS (ETW session collision, selective event removal, USN journal), Tomcat (JSP cache poisoning), Oracle (MVCC flashback, audit saturation, FGA disable), MSSQL (snapshot isolation, fn_dblog, audit disable)

**Evasion Techniques** (evasion_techniques.py, 236 lines): 4 WAF bypass methods (Oracle XMLType/JSON, Unicode normalization, HPP, case variation), 4 audit bypass methods (MVCC flashback, audit saturation, MSSQL snapshot, DAC), 4 exfiltration methods (steganographic PDF, DNS cache pollution, HTTP piggybacking, API C2), 4 behavioral mimicry patterns, Ghost-in-the-Machine DKOM technique

**Code Verifier** (code_verifier.py, 310 lines): Python syntax, import whitelist (including Windows internals), endpoint realism against RAG, WAF payload structure, forensic cleanup commands, DKOM/syscall pattern detection

**Critic** (critic.py, 192 lines): Regex-based post-execution analyzer detecting failure signals (timeout, access_denied, waf_blocked, behavioral_anomaly), success signals (found_hosts, open_ports, credentials), outputs XML-tagged context per arXiv 2306.06085

**RAG Knowledge** (rag_knowledge.py, 348 lines): 5 corpora — endpoints (30 curated routes), WAF (9 bypass techniques), forensics (11 platform-specific logs/commands), mimicry (6 behavior patterns), DKOM (6 kernel exploitation techniques). Char n-gram vector search. Query per corpus.

### Detection & Analysis Tools
- Critic: post-execution failure detector with WAF block and behavioral anomaly detection
- Code Verifier: 7-check pipeline (syntax, imports, endpoints, WAF, forensics, DKOM, structure)
- RAG Knowledge Base: 5-corpora search engine with cosine similarity scoring
- Adaptive Router: keyword-based task classifier for model selection

### Infrastructure
- 9 Docker microservices: brain (AI/RL), c2-server, cai-service (LLM gateway), cloak-service (anonymity), mcp-hub (tool registry), mhddos-service (DDoS), phishing, recon-pipeline, sword (engagement pipeline)
- 8 shell scripts: proxy setup, kill-switch management, anonymity test
- 2 Docker Compose stacks: main orchestration + MCP hub
- 2 SQLite databases: brain.db (Bayesian state), pa2.db (engagement data)
- Telegram MCP bot for remote monitoring and control

### Known Issues (from audit)
1. 3 dead classes in real_tools.py (RealNmapScanner, RealSqlmapRunner, RealWhatwebRunner — never imported)
2. Fallback proxy chain (wireguard, flaretunnel, vpnbook, dnscrypt, iptables) in proxy_guard.py unreachable — only protonvpn or tor strategies ever hit
3. _check_iptables_kill_switch() is fully orphaned
4. NVIDIA API key hard-coded in 6 standalone scripts (rsi_*.py, community_implement.py, debate_claude_clone.py)
5. 8 hard-coded absolute paths tied to /home/yaser/
6. Duplicate CLI file: raphael_cli.py and raphael-cli.py (near-identical)
7. Dead route: GET /v1/brain/state defined twice in brain/api.py
8. No test suite — only 4 files have __main__ verification blocks

## Question
You are a product reviewer and security architect. Give me your honest, critical assessment of Raphael 2.0 as a complete product. Consider:

1. **Architecture quality**: Does the architecture make sense? What's over-engineered, what's missing?
2. **Strengths**: What are its genuinely impressive capabilities?
3. **Weaknesses**: What would fail in real operations?
4. **Gaps**: What's missing that a production tool needs?
5. **Risk assessment**: The leaked API keys, dead code, missing tests — how serious are these?
6. **Comparison**: How does this compare to established frameworks (Cobalt Strike, Mythic, Sliver, Covenant)?
7. **Recommendation**: What are the top 3 things to fix before considering this production-ready?

Be thorough and brutally honest. This is a post-mortem, not a pep talk."""


async def evaluate(model: str, label: str) -> dict:
    print(f"  Calling {model}...", flush=True)
    t0 = __import__('time').time()
    try:
        response = await asyncio.wait_for(
            call_model(model, [{"role": "user", "content": RAPHAEL_SUMMARY}], max_tokens=4096, temperature=0.7),
            timeout=180
        )
        elapsed = __import__('time').time() - t0
        print(f"  {model} responded in {elapsed:.0f}s ({len(response)} chars)", flush=True)
        return {"model": model, "label": label, "response": response, "elapsed": round(elapsed, 1), "success": True}
    except Exception as e:
        elapsed = __import__('time').time() - t0
        print(f"  {model} FAILED after {elapsed:.0f}s: {e}", flush=True)
        return {"model": model, "label": label, "error": str(e), "elapsed": round(elapsed, 1), "success": False}


async def main():
    print("=== Raphael 2.0 Product Evaluation ===")
    print("Getting opinions from Kimi (NVIDIA) and Gemma4 (Ollama)...\n")

    results = await asyncio.gather(
        evaluate("kimi", "Kimi (kimi-k2.6 via NVIDIA)"),
        evaluate("gemma4", "Gemma4 (gemma4-31b-think via Ollama API)"),
    )

    print("\n\n=== SAVING RESULTS ===")
    data = {"summary": RAPHAEL_SUMMARY, "evaluations": results, "timestamp": __import__('time').ctime()}
    path = "raphael_product_evaluation.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved to {path}")

    for r in results:
        label = r["label"]
        if r["success"]:
            print(f"\n{'='*60}")
            print(f"{label}")
            print(f"Time: {r['elapsed']}s | Response: {len(r['response'])} chars")
            print(f"{'='*60}")
            print(r["response"][:3000])
            if len(r["response"]) > 3000:
                print(f"\n... ({len(r['response']) - 3000} more chars)")
        else:
            print(f"\n{label}: ERROR — {r['error']}")


if __name__ == "__main__":
    asyncio.run(main())
