import asyncio, json, httpx, os, time

NVIDIA_KEY = os.getenv("NVIDIA_API_KEY")
if not NVIDIA_KEY:
    raise RuntimeError("NVIDIA_API_KEY environment variable required")
NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
OLLAMA_URL = "http://localhost:11434/v1/chat/completions"

MODELS = [
    ("deepseek", {"id": "deepseek-ai/deepseek-v4-flash",  "api": "nvidia"}),
    ("minimax",  {"id": "minimaxai/minimax-m3",           "api": "nvidia"}),
    ("glm51",    {"id": "z-ai/glm-5.1",                   "api": "nvidia"}),
]

TOPIC = """RAPHAEL 2.0 CODEBASE AUDIT (what actually exists):
- 6 microservices: cai-service, cloak-service, mhddos-service, c2-server, phishing, recon-pipeline
- MCP Hub with 7 tool categories, 12 tool implementations, auth/scope/audit logging
- SWORD offensive pipeline: 6 phases (recon → scan → exploit → postex → exfil → phish)
- Orchestrator CLI with 6 modes: debate, community, rsi, scan, autonomous, plus 10+ secondary
- Adaptive Brain: Thompson sampling, UCB, PSO, circuit breakers, episodic+semantic memory
- Proxy Guard: multi-layer anonymity (Tor + WireGuard + FlareTunnel), DNS leak prevention
- SAST pipeline: 14 vulnerability patterns, LLM-based analysis
- All microservices have Dockerfiles, all run via docker-compose
- No tests except MCP Hub (6 tests)
- No modes/single.py, ensemble.py, pipeline.py, swarm.py, anon_rsi.py, sword_review.py
- No shared/ directory (scope/tor/encrypt scattered across modules)
- Provider routing uses NVIDIA API (121 models available), Ollama, Groq, FreeLLMAPI

CLAUDE CODE ECOSYSTEM DATA (from Claude-Clone/ directory):
1. KAIROS: perpetual daemon mode, terminal-focus detection, background subagents, GitHub webhooks
2. autoDream: 24h/5-session memory consolidation across sessions (not just per-engagement)
3. Undercover Mode: strip AI attribution from commits/PRs/exfiltrated data
4. Hook System: 25+ lifecycle events (PreToolUse, PostToolUse, UserPromptSubmit)
5. 5-Tier Context Compaction: microcompact → collapse → session memory → full → PTL truncation
6. Session Persistence: JSONL per session, --fork-session, --continue, --resume
7. CLAUDE.md hierarchy: 40K chars across global/project/private scope
8. Permission System: 5-level cascade (bypass, allowEdits, auto, classifier, deny)
9. Retry System: 10 retries exp backoff + jitter, OAuth refresh, model fallback
10. oh-my-openagent: Multi-model orchestration (Sisyphus pattern), hash-anchored edits, IntentGate
11. free-code: 54 unlocked flags including ULTRAPLAN, VERIFICATION_AGENT, AGENT_TRIGGERS
12. Subagent Model: fork (shared cache), teammate (tmux pane), worktree (isolated branch)"""

DEBATE_Q = """Compare Raphael 2.0's actual architecture against the Claude Code ecosystem features above.

For each Claude feature, answer:
1. Does Raphael have an equivalent? If yes, how does it compare?
2. Is there practical value in porting/adapting it to Raphael?
3. What's the actual effort-to-value ratio?

Finally: given that Raphael already has real working microservices, SWORD pipeline, MCP hub, adaptive brain, and proxy guard — is there ACTUAL practical use in integrating Claude Code patterns, or is Raphael already sufficient as-is?

Be specific. Reference actual filenames and line counts from the audit."""

async def call_model(model_cfg, prompt, temperature=0.7):
    if model_cfg["api"] == "nvidia":
        headers = {"Authorization": f"Bearer {NVIDIA_KEY}", "Content-Type": "application/json"}
        url = NVIDIA_URL
    else:
        headers = {"Content-Type": "application/json"}
        url = OLLAMA_URL

    payload = {
        "model": model_cfg["id"],
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2048,
        "temperature": temperature,
        "stream": False,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0)) as cl:
            resp = await cl.post(url, json=payload, headers=headers)
            txt = resp.text
            if not txt:
                return f"[ERROR: empty response, status={resp.status_code}]"
            body = resp.json()
            if "choices" not in body:
                return f"[ERROR: {json.dumps(body)[:500]}]"
            return body["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[ERROR: {type(e).__name__}: {str(e)[:200]}]"

async def main():
    print("=" * 70)
    print("RAPHAEL 2.0 — CLAUDE-CLONE UTILITY DEBATE")
    print("Models: GLM 5.1 | DeepSeek V4 Flash | MiniMax M3")
    print("=" * 70)

    contributions = {}
    rounds = 2

    for r in range(1, rounds + 1):
        print(f"\n{'='*70}\nROUND {r}/{rounds}\n{'='*70}")

        for name, cfg in MODELS:
            print(f"\n--- {name.upper()} (R{r}) ---")
            ctx = f"[ROUND {r}/{rounds}]\n\nContext: {TOPIC}\n\nQuestion: {DEBATE_Q}\n\n"
            if contributions:
                ctx += "Other models said:\n"
                for oname, ocontrib in contributions.items():
                    ctx += f"\n<{oname.upper()}>:\n{ocontrib[:1500]}\n"
                ctx += "\nNow add NEW perspectives. Challenge weak points. Propose concrete implementation steps not yet covered."
            else:
                ctx += "Present your analysis of which patterns are most valuable for Raphael 2.0."

            result = await call_model(cfg, ctx, temperature=0.85 if r == 1 else 0.9)
            contributions[name] = result
            print(result[:800])
            print(f"[{len(result)} chars]")

    print(f"\n{'='*70}")
    print("FINAL SYNTHESIS (MiniMax M3 — Reasoning)")
    print(f"{'='*70}")

    all_contribs = ""
    for name, contrib in contributions.items():
        all_contribs += f"<{name.upper()}>:\n{contrib}\n\n"

    synthesis_prompt = f"""Context: {TOPIC}

All debate contributions:
{all_contribs}

Synthesize the strongest unified answer. Provide:
1. Ranked recommendations (copy vs study vs skip) with rationale
2. Implementation priority order for Raphael 2.0
3. Risk assessment of porting TypeScript patterns to Python
4. Concrete next steps (file-by-file if relevant)"""

    final = await call_model(
        MODELS[2][1],  # minimax
        synthesis_prompt,
        temperature=0.3
    )

    print(final)

    output = {
        "topic": "Claude-Clone utility for Raphael 2.0",
        "models": {n: c["id"] for n, c in MODELS},
        "rounds": rounds,
        "contributions": {n.upper(): c for n, c in contributions.items()},
        "synthesis": final,
    }

    outpath = "/home/yaser/Ultimate skill/raphael-2.0/orchestrator/debate_claude_clone_output.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to {outpath}")

asyncio.run(main())
