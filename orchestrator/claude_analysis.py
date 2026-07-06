#!/usr/bin/env python3
"""Analyze Claude Code patterns for Raphael applicability using minimax-m3."""

import asyncio, json, httpx, sys, os

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
MODEL = "minimax-m3:cloud"

RAPHAEL_AUDIT = """Raphael 2.0 is a working autonomous security platform with:
- 6 microservices (cai, cloak, mhddos, c2, phishing, recon-pipeline)
- MCP Hub with 12 tools across 7 categories
- SWORD pipeline: recon -> scan -> exploit -> postex -> exfil -> phish
- Adaptive brain: Thompson sampling, UCB, PSO model selection
- Proxy guard: Tor + WireGuard + FlareTunnel + DNS leak + jitter
- 7900 lines Python, real binaries (nmap, sqlmap, nuclei), real engagement results
- No tests (except MCP hub), no session fork/resume, basic retry logic"""

CLAUDE_PATTERNS = """Claude Code ecosystem patterns found:

1. KAIROS: perpetual daemon mode, terminal-focus detection, background subagents, GitHub webhooks
2. autoDream: 24h/5-session memory consolidation across engagements
3. Undercover: strip AI attribution from commits/exfil data
4. Hook system: 25+ lifecycle events (PreToolUse, PostToolUse)
5. 5-tier context compaction: microcompact -> collapse -> session memory -> full -> PTL truncation
6. Session persistence: JSONL per session, --fork-session, --continue, --resume
7. CLAUDE.md hierarchy: 40K chars global/project/private context
8. Permission system: 5-level cascade (bypass, allowEdits, auto, classifier, deny)
9. Retry system: 10 retries exp backoff+jitter, OAuth refresh, model fallback
10. Subagent model: fork (shared cache), teammate (tmux pane), worktree (isolated branch)
11. oh-my-openagent: Sisyphus orchestrator, hash-anchored edits, IntentGate
12. free-code: 54 flags (ULTRAPLAN, VERIFICATION_AGENT, AGENT_TRIGGERS)"""

ANALYSIS_QUESTION = f"""Given Raphael's actual architecture and the Claude Code ecosystem patterns, analyze each pattern for practical value:

Raphael:
{RAPHAEL_AUDIT}

Claude Patterns:
{CLAUDE_PATTERNS}

For EACH of the 12 patterns above, give:
- SCORE: 1-10 (10 = must port, 1 = irrelevant)
- EFFORT: X lines of code
- REASON: one sentence why

Then rank top 5 by score/effort ratio. Be specific. Reference actual Raphael files.""" 

async def call_model(prompt, temperature=0.3):
    async with httpx.AsyncClient(timeout=180) as cl:
        resp = await cl.post(OLLAMA_URL, json={
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,
            "temperature": temperature,
            "stream": False,
        })
        body = resp.json()
        return body["choices"][0]["message"]["content"]

async def main():
    print(f"Analyzing Claude patterns via {MODEL}...\n")
    
    # Round 1: Initial analysis
    print("=== ROUND 1: Pattern Analysis ===")
    r1 = await call_model(ANALYSIS_QUESTION, temperature=0.3)
    print(r1)
    print("\n" + "="*60 + "\n")
    
    # Round 2: Implementation priorities
    print("=== ROUND 2: Implementation Plan ===")
    r2_prompt = f"""Based on this analysis:
{r1}

Now produce a concrete implementation plan. For the top 3 patterns:
1. Which exact file(s) to modify
2. What to add (pseudocode ok)
3. How it connects to existing code

Be brief and practical. Focus on raphael-2.0/orchestrator/ files."""
    r2 = await call_model(r2_prompt, temperature=0.3)
    print(r2)
    
    # Save results
    output = {"round1": r1, "round2": r2, "model": MODEL}
    outpath = "/home/yaser/Ultimate skill/raphael-2.0/orchestrator/claude_analysis_result.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {outpath}")

asyncio.run(main())
