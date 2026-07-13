#!/usr/bin/env python3
"""RSI analysis: What Hermes Agent UI code is worth porting into Raphael 2.0?"""

import asyncio, json, time, sys, os
from orchestrator.providers import call_model

TEAM = {
    "kimi": "oc-kimi",
    "nemotron-ultra": "oc-nemotron-ultra",
}

TASK = """You are evaluating HERMES AGENT (by Nous Research, 208k stars) for UI/UX patterns that could be ported into RAPHAEL 2.0, an autonomous offensive security platform.

RAPHAEL 2.0 (existing):
- 10 Docker microservices with a FastAPI orchestrator
- Currently has NO UI beyond CLI python scripts
- Has a separate orchestrator/ directory with FastAPI
- Has an MCP hub at :3500
- Users currently interact via: python app.py <mode> <args>
- No real-time streaming, no web dashboard, no messaging integration
- Outputs: JSON to stdout, markdown files to engagements/

HERMES AGENT UI ARCHITECTURE (cloned at /tmp/hermes-agent):

1. TUI GATEWAY (tui_gateway/) — JSON-RPC over stdio/WebSocket
   - server.py: Single dispatch() function handling ALL RPC methods
   - transport.py: Transport protocol abstraction (StdioTransport, WebSocket)
   - ws.py: WebSocket transport, reuses dispatch() verbatim, batch flushes token deltas
   - event_publisher.py: Mirrors gateway emits to dashboard WebSocket sidecar
   - entry.py: stdio entry point, signal handlers, main read->dispatch->write loop
   - Pattern: ONE dispatch(), MULTIPLE transports (stdio, WS). Adding a transport = implementing write(json_dict).

2. REACT WEB UI (web/) — Vite 8 + React 19 + TypeScript 6 + Tailwind CSS 4
   - Single page app served by Python FastAPI dashboard server
   - api.ts: Typed fetch wrappers, SSE streaming, WebSocket auth tickets
   - SystemActions context: global refresh/shutdown
   - Pages: StatusPage (agent status, active/recent sessions), ConfigPage (dynamic config), EnvPage (API keys)
   - Builds to hermes_cli/web_dist/

3. INK TUI (ui-tui/) — React for terminal
   - ink + react 19 + nanostores + undici WebSocket
   - GatewayClient: JSON-RPC over stdio (or WS) with typed GatewayEvent emitter
   - useMainApp: Central state orchestrator (transcript, composer, progress, status, scroll, session)
   - Nanostore-backed state modules (turnStore, uiStore)

4. MESSAGING GATEWAY (gateway/) — Telegram, Discord, Slack, WhatsApp, Signal
   - BasePlatformAdapter ABC: send_message, send_media, edit_message, react, render_message_event
   - stream_events.py: Typed event dataclasses (MessageChunk, ToolCallChunk, Commentary, GatewayNotice, ToolCallFinished)
   - stream_dispatch.py: Routes typed events through adapter's render hooks
   - stream_consumer.py: Bridges sync agent callbacks to async adapter delivery via queue.Queue
   - Hook system (hooks.py): HookRegistry fires at lifecycle points (agent:start, agent:step, agent:end)
   - Relay adapter: Generic adapter that fronts ANY platform via stdio/WS connector

5. CLI (cli.py, hermes_cli/) 
   - Modern CLI entry: hermes <command> dispatcher
   - FastAPI web server serving dashboard SPA + REST API
   - Dashboard auth module

6. AGENT LOOP (agent/conversation_loop.py)
   - run_conversation(): Drives one user turn through model call, tool dispatch, retries, fallbacks, compression
   - Interfaces with UIs via callbacks + stream_events contract
   - Background review, context engine, memory manager

YOUR JOB: Evaluate each component for porting into Raphael 2.0:

A) JSON-RPC transport layer (tui_gateway/server.py, transport.py, ws.py)
B) Web dashboard (web/ + hermes_cli/web_server.py) 
C) Ink TUI (ui-tui/)
D) Messaging gateway pattern (gateway/stream_events, stream_dispatch, BasePlatformAdapter)
E) Agent-to-UI event vocabulary (stream_events.py)
F) CLI pattern (hermes_cli/main.py)
G) Hook system (gateway/hooks.py)

For EACH, provide:
- SCORE (1-10): value to port to Raphael 2.0
- Effort estimate (LOC + files)
- Specific raphael-2.0 file paths where it should integrate
- What would NOT port (Hermes-specific code that must be rewritten)
- Whether to: PORT (implement it), REUSE (copy/modify Hermes files), INSPIRE (take the pattern, write from scratch), or SKIP

Focus on: Which parts give Raphael a real UI with the least effort? The web dashboard is the highest priority because Raphael needs a visual interface for engagement monitoring and control."""

SYNTHESIS_TASK = """You are the lead architect synthesizing a team's analysis of what UI/UX patterns from Hermes Agent to port into Raphael 2.0.

TEAM MEMBER ANALYSES:

{d}

YOUR JOB: Produce the FINAL PORTING PLAN. Include:
1. A table of ALL components (A-G) with score, effort, verdict
2. Ranked priority order — what to build first, second, third
3. Architecture diagram: how the UI layer would sit on top of Raphael's existing services
4. Specific Hermes files that can be directly copied/referenced (with paths)
5. What MUST be rewritten (security-specific, Raphael-specific)
6. Estimated total LOC and timeline

Be decisive. One unified recommendation. No hedging."""

async def safe_call(name, alias, prompt, temperature=0.3, max_tokens=2048):
    t0 = time.time()
    print(f"  Starting {name}...", flush=True)
    try:
        result = await call_model(alias, [{"role": "user", "content": prompt}], temperature, max_tokens)
        elapsed = time.time() - t0
        print(f"  {name} done ({elapsed:.0f}s) {len(result)} chars", flush=True)
        return name, result
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  {name} FAILED ({elapsed:.0f}s): {type(e).__name__}", flush=True)
        return name, f"[ERROR: {type(e).__name__}: {e}]"


async def main():
    print("=" * 70, flush=True)
    print("RSI ANALYSIS: Hermes Agent UI Patterns × Raphael 2.0", flush=True)
    print(f"Team: {', '.join(TEAM.keys())}", flush=True)
    print("=" * 70 + "\n", flush=True)

    all_results = {}

    print("▶ Phase 1: Independent Analysis\n", flush=True)
    tasks = [safe_call(name, TEAM[name], TASK, temperature=0.4) for name in TEAM]
    done = await asyncio.gather(*tasks)

    for name, result in done:
        all_results[name] = result

    print("\n" + "=" * 70, flush=True)
    print("▶ Phase 2: Cross-Critique\n", flush=True)

    critique_text = ""
    for name, text in all_results.items():
        critique_text += f"\n=== {name} ===\n{text}\n"

    critique_prompt = f"""Read both analyses below. Then give a CRITIQUE:

1. Which analysis is more accurate? Where do they differ?
2. What did each model miss?
3. Give your UPDATED scores and verdicts for components A-G.
4. What's the ONE thing Raphael should build first from Hermes?

{critique_text}
"""

    critique_tasks = [safe_call(f"{name}_critique", TEAM[name], critique_prompt, temperature=0.3) for name in TEAM]
    critiques = await asyncio.gather(*critique_tasks)
    for name, text in critiques:
        all_results[name] = text

    print("\n" + "=" * 70, flush=True)
    print("▶ Phase 3: Final Synthesis\n", flush=True)

    synthesis_input = ""
    for name, text in all_results.items():
        synthesis_input += f"\n=== {name} ===\n{text}\n"

    _, final = await safe_call(
        "kimi-synthesis", TEAM["kimi"],
        SYNTHESIS_TASK.format(d=synthesis_input),
        temperature=0.2, max_tokens=8192
    )

    print(final, flush=True)
    print("\n" + "=" * 70, flush=True)
    print("SAVING REPORT...", flush=True)

    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "rsi_hermes_ui_report.json"), "w") as f:
        json.dump({
            "task": "Hermes Agent UI Patterns × Raphael 2.0",
            "team": TEAM,
            "phase1": all_results,
            "phase3_synthesis": final,
        }, f, indent=2)

    with open(os.path.join(out_dir, "rsi_hermes_ui_plan.md"), "w") as f:
        f.write(final)

    print("Saved to rsi_hermes_ui_report.json and rsi_hermes_ui_plan.md", flush=True)
    print("\nDONE.", flush=True)


asyncio.run(main())
