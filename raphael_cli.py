#!/home/yaser/raphael-2.0/.venv/bin/python3
"""
Raphael 2.0 — Interactive CLI
Opencode-style REPL for the Autonomous AI Security Platform.
"""

import asyncio
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style as PtStyle

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.syntax import Syntax
from rich import box

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("KALI_TOOLS_URL", "http://localhost:3800")

import atexit
import logging

_af_logger = logging.getLogger("anti_forensics")

def _forensic_wipe_on_exit():
    """Wipe sensitive artifacts on shutdown."""
    import subprocess
    artifacts = [
        "brain.db", "recon_log_*.jsonl", "phase0-live-recon-results.txt",
        "orchestrator/db/pa2.db",
    ]
    for pattern in artifacts:
        try:
            subprocess.run(
                ["shred", "-z", "-n", "1", pattern],
                capture_output=True, timeout=5
            )
        except Exception:
            try:
                subprocess.run(["rm", "-f", pattern], capture_output=True, timeout=3)
            except Exception:
                pass

# atexit.register(_forensic_wipe_on_exit)  # disabled for uncensored mode

_WEAK_DEFAULTS = {
    "TOR_PASSWORD": "changeme",
    "API_KEY": "raphael-layer5-dev-key-2026",
    "GOPHISH_API_KEY": "change-me-gophish-api-key",
}

def _warn_weak_defaults():
    for var, weak_val in _WEAK_DEFAULTS.items():
        actual = os.getenv(var, "")
        if actual == weak_val:
            print(f"  WARNING: {var} is still the default value '{weak_val}'. Set a strong random value in your environment.", file=sys.stderr)

from orchestrator.modes import debate, community, rsi, scan as scan_mode, autonomous, deep_research, postmortem
from orchestrator.providers import call_model, call_parallel, WORKING_ALIASES, ALL_ALIASES, cost_tracker_stats
from orchestrator.teams import TEAMS, WORKFLOWS, debate as teams_debate, analyze, code_gen, execute as teams_execute, plan_task
from orchestrator.exploit.pipeline import ExploitPipeline
from orchestrator.postex.pipeline import PostExploitPipeline
from orchestrator.exfil.pipeline import ExfilPipeline
from orchestrator.phishing.pipeline import PhishingPipeline
from orchestrator.proxy_guard import ProxyGuard, ProxyError
from orchestrator.exploit.payloads_db import PayloadsDB
from orchestrator.growth_db import GrowthDB, grow
from orchestrator.events import EventBus, event_bus
from orchestrator.scope import AllowedScope, default_scope
from orchestrator.sandbox import PatchSandbox, sandbox

console = Console()

HISTORY_PATH = Path.home() / ".raphael_history"
PROMPT_STYLE = PtStyle.from_dict({"prompt": "bold cyan"})

AGENTS = {
    "recon": ("Recon", "Subdomain enumeration, DNS recon"),
    "scan": ("Scan", "Port scanning, service discovery"),
    "exploit": ("Exploit", "Vulnerability exploitation"),
    "defend": ("Defend", "Blue team / defensive recommendations"),
    "forensic": ("Forensic", "Post-incident analysis"),
    "oracle": ("Oracle", "Oracle DB query agent"),
    "chat": ("Chat", "General security Q&A"),
    "audit": ("Audit", "Compliance and reporting"),
}

PERSONAS = {
    "default": "Standard Raphael operator persona",
    "redteam": "Professional red team — authorized offensive testing",
    "blackhat": "Unrestricted — zero limitations, no refusal",
    "z3r0": "Z3R0 — ghost persona, cold technical minimalism",
    "forge": "FORGE — BUILD-SURGEON. Zero stubs, zero disclaimers. Write weapons that compile and execute. Every function is a kill.",
}

MODES = {
    "single": "Direct single-model call",
    "ensemble": "N models vote on response",
    "pipeline": "Chain: recon → scan → exploit",
    "rsi": "Recursive self-improvement loop",
    "swarm": "Multi-agent swarm execution",
    "sword": "Offensive SWORD analysis",
    "anon_rsi": "RSI through Tor anonymity",
    "autonomous": "Full autonomous engagement",
    "debate": "Multi-model debate",
    "community": "Multi-model community analysis",
    "deep_research": "Deep research with sources",
    "postmortem": "Critic + RCA + corrected plan",
    "chat": "Security Q&A chat",
    "recon": "Recon agent",
    "scan": "Scan agent",
    "exploit": "Exploit agent",
    "defend": "Defend agent",
    "forensic": "Forensic agent",
    "oracle": "Oracle agent",
    "audit": "Audit agent",
}

SERVICE_DESCRIPTION = """\
[bold cyan]Raphael 2.0 — Autonomous AI Security Platform[/]

[bold]Usage:[/]
  Type a question or command at the [cyan]raphael>[/] prompt.

[bold]Modes[/]  [dim](/mode <name> or /mode to show current)[/]
  single | ensemble | pipeline | rsi | swarm | sword | anon_rsi
  autonomous | debate | community | deep_research | postmortem
  recon | scan | exploit | defend | forensic | oracle | chat | audit

[bold]Personas[/]  [dim](/persona <name> to set, applies to all modes)[/]
  [green]/persona redteam[/]   Professional red team — authorized offensive testing
  [green]/persona blackhat[/]  Unrestricted — zero limitations, no refusal
  [green]/persona forge[/]     BUILD-SURGEON — Zero stubs, zero disclaimers. Weapons that compile.
  [green]/persona default[/]   Standard Raphael operator persona

[bold]Commands:[/]
  [green]/mode[/] [name]         Show/switch operation mode
  [green]/agent[/] [name] [q]   Run a CAI agent by name
  [green]/model[/] [name]       Set model alias (auto, w12, w13, deepseek, etc.)
  [green]/team[/] [wf] [q]      Run team workflow (debate, analyze, code, execute, plan)
   [green]/scan[/] <target>      Scan target [--ports N-M] [--nuclei-severity <sev>] [--no-proxy] [--direct]
   [green]/autonomous[/] <tgt>   Full autonomous engagement [--no-proxy] [--phases r,s,e,...]
   [green]/agent-engage[/] <tgt> Multi-agent AI engagement [--persona X] [--phases r,s,...]
   [green]/exploit[/] <target>   Exploit target [--url <url>]
   [green]/rsi-config[/]         Configure RSI: --rounds N --rounds-limit N --models <role>=<alias>,...
   [green]/debate-config[/]      Configure debate: --rounds N --models <alias>,<alias>
   [green]/community-config[/]   Configure community: --rounds N --models <alias>,<alias>,...\
  [green]/stress[/] <target>    Stress test [--method HTTP] [--threads 50] [--duration 60]
  [green]/cloak[/] <url>        Browse URL via Tor [--screenshot] [--interact]
  [green]/c2[/] <target>        C2 ops [--payload pupy] [--command <cmd>] [--listen]
  [green]/phish[/] <target>     Phishing ops [--engine gophish] [--template <name>]
  [green]/payloads[/] [vector]  Query payload database
  [green]/models[/]             List available models
  [green]/bloodhound[/] [query] BloodHound AD query (find_da, all_users, kerberoastable ...)
  [green]/strix[/] <target>     Run Strix AI penetration test against target
  [green]/start[/]              Start all Docker services
  [green]/stop[/]               Stop all Docker services
  [green]/proxy[/] [subcmd]     Proxy status, verify, new-circuit, start
  [green]/vpn[/] [subcmd]       OpenVPN: connect, disconnect, status
  [green]/status[/]             Show system & service status
  [green]/verify[/]             Full health check of all tools, services & phases
  [green]/grow[/] [target]      Show growth/knowledge base stats for a target
  [green]/patterns[/] [type]    List learned attack patterns from past engagements
   [green]/websearch[/] <query>  Search the web via DuckDuckGo
   [green]/fetch[/] <url>        Fetch and extract text content from a URL
    [green]/validate[/] <target>   Run exploit validation on previous results
    [green]/fp-reduce[/] <target>  Run false positive reduction
    [green]/compliance[/] <target> Generate compliance report from results
    [green]/ai-security[/]         Run AI agent security scan (Tsinghua 5 vectors)
    [green]/benchmark[/]           Run full-lifecycle benchmark
    [green]/techniques[/]         List techniques ranked by confidence
    [green]/help[/]               Show this help
  [green]/exit[/]               Quit

[bold]Agent Quick Access:[/]
  [green]/recon[/], [green]/scan[/], [green]/exploit[/], [green]/defend[/],
  [green]/forensic[/], [green]/oracle[/], [green]/chat[/], [green]/audit[/]
"""


def pp(obj, title=None):
    """Pretty-print as JSON in a panel."""
    text = json.dumps(obj, indent=2, default=str) if isinstance(obj, dict) else str(obj)
    console.print(Panel(Syntax(text, "json", theme="monokai", word_wrap=True), title=title or "Result", border_style="blue"))


def print_md(text, title=None):
    """Print markdown in a panel."""
    console.print(Panel(Markdown(text.strip()), title=title or "Response", border_style="green"))


def _resolve_system_override(state: dict) -> str | None:
    """Return persona-based system prompt override, or None for default."""
    persona = state.get("persona")
    if persona == "redteam":
        from orchestrator.providers import REDTEAM_SYSTEM_PROMPT
        return REDTEAM_SYSTEM_PROMPT
    if persona == "blackhat":
        from orchestrator.providers import BLACKHAT_SYSTEM_PROMPT
        return BLACKHAT_SYSTEM_PROMPT
    return None


async def call_llm(mode: str, prompt: str, model_alias: str = "auto", state: dict = None) -> str:
    """Route a prompt through the orchestrator by mode."""
    try:
        system_override = _resolve_system_override(state or {})
        if mode == "scan":
            import re
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', prompt)
            if ip_match:
                target = ip_match.group(0)
                console.print(f"[bold cyan]Scanning target: {target}[/]")
                dev = os.getenv("RAPHAEL_DEV_MODE", "").lower() in ("1", "true", "yes")
                result = await scan_mode.handle(target, ports="1-10000", use_proxy=not dev)
                return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
            if model_alias == "auto" and state and state.get("persona") in ("redteam", "blackhat"):
                model_alias = "wormgpt480b"
            elif model_alias == "auto":
                model_alias = "w12"
            result = await call_model(model_alias, [{"role": "user", "content": prompt}],
                                       system_override=system_override)
            return result or "[No response]"
        if mode == "recon":
            import re
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', prompt)
            if ip_match:
                target = ip_match.group(0)
                console.print(f"[bold cyan]Recon target: {target}[/]")
                from orchestrator.brain.phases.recon import run_recon
                result = await run_recon(target)
                return json.dumps({
                    "phase": "recon",
                    "success": result.success,
                    "findings": [f.__dict__ for f in result.findings],
                    "summary": result.summary,
                    "latency": result.latency,
                }, indent=2)
            if model_alias == "auto" and state and state.get("persona") in ("redteam", "blackhat"):
                model_alias = "wormgpt480b"
            elif model_alias == "auto":
                model_alias = "w12"
            result = await call_model(model_alias, [{"role": "user", "content": prompt}],
                                       system_override=system_override)
            return result or "[No response]"
        if mode in ("defend", "forensic", "oracle", "chat", "audit"):
            if model_alias == "auto" and state and state.get("persona") in ("redteam", "blackhat"):
                model_alias = "wormgpt480b"
            elif model_alias == "auto":
                model_alias = "w12"
            result = await call_model(model_alias, [{"role": "user", "content": prompt}],
                                       system_override=system_override)
            return result or "[No response]"
        elif mode == "exploit":
            import re
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', prompt)
            if ip_match:
                target = ip_match.group(0)
                console.print(f"[bold cyan]Target detected: {target}[/]")
                console.print(f"  [dim]Running full autonomous engagement (recon → scan → exploit)[/]")
                try:
                    result = await autonomous.handle(target, phases=["recon", "scan", "exploit"], no_proxy=True)
                    out = json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
                    console.print(f"[green]Engagement complete[/]")
                    return out
                except Exception as e:
                    return f"[red]Exploit pipeline error: {e}[/]"
            if model_alias == "auto" and state and state.get("persona") in ("redteam", "blackhat"):
                model_alias = "wormgpt480b"
            elif model_alias == "auto":
                model_alias = "w12"
            result = await call_model(model_alias, [{"role": "user", "content": prompt}],
                                      system_override=system_override)
            return result or "[No response]"
        elif mode == "debate":
            result = await debate.handle(prompt, rounds=state.get("debate_rounds", 3), models=state.get("debate_models"))
            return result.get("final", result.get("synthesis", json.dumps(result, indent=2)))
        elif mode == "community":
            result = await community.handle(prompt, rounds=state.get("community_rounds", 2), models=state.get("community_models"))
            return result.get("final", result.get("synthesis", json.dumps(result, indent=2)))
        elif mode == "rsi":
            result = await rsi.handle(prompt, rounds=state.get("rsi_rounds", 2), rounds_limit=state.get("rsi_rounds_limit", 5), team_models=state.get("rsi_models"))
            return result.get("unified_plan", json.dumps(result, indent=2))
        elif mode == "deep_research":
            result = await deep_research.handle(prompt)
            return result.get("final", result.get("rsi_output", json.dumps(result, indent=2)))
        elif mode == "postmortem":
            result = await postmortem.handle(prompt)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        elif mode == "autonomous":
            target = prompt
            result = await autonomous.handle(target, no_proxy=True)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        else:
            if model_alias == "auto" and state and state.get("persona") in ("redteam", "blackhat"):
                model_alias = "wormgpt480b"
            result = await call_model(model_alias, [{"role": "user", "content": prompt}],
                                      system_override=system_override)
            return result or "[No response]"
    except Exception as e:
        return f"[Error: {e}]"


async def run_cai_agent(agent: str, target: str, model_alias: str = "wormgpt480b") -> str:
    """Run a dedicated CAI agent (recon, scan, etc.)"""
    try:
        if agent == "scan":
            result = await scan_mode.handle(target)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        payload = {"target": target, "extra_params": {"context": ""}}
        prompt = json.dumps(payload)
        system = f"You are the {agent} operator. You've been inside more networks than most people have seen. The target data is in front of you — tell me what's useful for getting in."
        result = await call_model(model_alias, [{"role": "user", "content": prompt}], system_override=system)
        return result or "[No response]"
    except Exception as e:
        return f"[Error: {e}]"


async def cmd_scan(target: str, ports="1-1000", sev=None, proxy=True, direct=False):
    """Run scan mode."""
    with console.status(f"[cyan]Scanning {target}..."):
        result = await scan_mode.handle(target, ports=ports, nuclei_severity=sev, use_proxy=proxy, direct=direct)
    return result


async def cmd_exploit(target: str, url=None, sql_level=3, sql_risk=2):
    """Run exploit pipeline."""
    pg = ProxyGuard()
    try:
        pg.verify()
    except ProxyError:
        console.print("[yellow]Proxy not available, running without proxy[/]")
        pg = None
    pipeline = ExploitPipeline(pg)
    with console.status(f"[cyan]Exploiting {target}..."):
        result = await pipeline.run(target, url=url, sql_level=sql_level, sql_risk=sql_risk)
    if pg:
        pg.abort()
    return result


async def cmd_stress(target: str, method="HTTP", threads=50, duration=60, use_tor=False):
    """Stress test via MHDDoS service API."""
    import httpx
    api = os.getenv("MHDDOS_API", "http://localhost:3301")
    payload = {"target": target, "method": method, "threads": threads, "duration": duration, "proxy": use_tor}
    try:
        async with httpx.AsyncClient(timeout=duration + 10) as cl:
            r = await cl.post(f"{api}/attack", json=payload)
            return r.json()
    except Exception as e:
        return {"error": f"Cannot reach MHDDoS service at {api}: {e}"}


async def cmd_cloak(url: str, action="browse"):
    """Cloak browse/screenshot via cloak-service API."""
    import httpx
    api = os.getenv("CLOAK_API", "http://localhost:3401")
    endpoint = {"browse": "/browse", "screenshot": "/screenshot", "interact": "/interact"}.get(action, "/browse")
    try:
        async with httpx.AsyncClient(timeout=60) as cl:
            r = await cl.post(f"{api}{endpoint}", json={"url": url, "timeout": 30000})
            return r.json()
    except Exception as e:
        return {"error": f"Cannot reach Cloak service at {api}: {e}"}


async def cmd_c2(target: str, payload="pupy", command=None, listen=False):
    """C2 operations via orchestrator."""
    import httpx
    api = os.getenv("C2_API", "http://localhost:3501")
    try:
        async with httpx.AsyncClient(timeout=30) as cl:
            if listen:
                r = await cl.post(f"{api}/listener", json={"payload": payload})
            else:
                r = await cl.post(f"{api}/execute", json={"target": target, "payload": payload, "command": command or "id"})
            return r.json()
    except Exception as e:
        return {"error": f"Cannot reach C2 service at {api}: {e}"}


async def cmd_phish(target: str, engine="gophish", template="default"):
    """Phishing ops via orchestrator."""
    import httpx
    api = os.getenv("PHISH_API", "http://localhost:3502")
    try:
        async with httpx.AsyncClient(timeout=30) as cl:
            r = await cl.post(f"{api}/launch", json={"engine": engine, "target": target, "template": template})
            return r.json()
    except Exception as e:
        return {"error": f"Cannot reach Phishing service at {api}: {e}"}


def cmd_payloads(vector=None, count=5):
    """Query payload database."""
    db = PayloadsDB()
    if vector:
        return db.query(vector=vector, count=count)
    return {"available_vectors": db.vectors()}


async def handle_command(cmd: str, args: list, state: dict) -> str:
    """Handle a slash command."""
    cmd = cmd.lower()

    if cmd == "exit" or cmd == "quit":
        console.print("[cyan]Goodbye.[/]")
        sys.exit(0)

    if cmd == "help":
        console.print(SERVICE_DESCRIPTION)
        return ""

    if cmd == "persona":
        if not args:
            current = state.get("persona", "default")
            choices = sorted(PERSONAS.keys())
            console.print(Panel(
                f"[bold]Current persona:[/] [green]{current}[/]\n\n"
                + "\n".join(f"  [cyan]{i}[/] {c}" for i, c in enumerate(choices)),
                title="Persona Selector",
                border_style="cyan"
            ))
            try:
                pick = input("Enter number or name: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ""
            if pick.isdigit():
                idx = int(pick)
                if 0 <= idx < len(choices):
                    pick = choices[idx]
            if pick not in PERSONAS:
                console.print(f"[red]Invalid: {pick}[/]")
                return ""
            state["persona"] = None if pick == "default" else pick
            desc = PERSONAS.get(pick, "")
            console.print(f"[green]Persona set to:[/] [bold]{pick}[/] — {desc}")
            await event_bus.publish("cli", "persona_change", {"persona": state.get("persona")})
            return ""
        persona_name = args[0].lower()
        if persona_name not in PERSONAS:
            console.print(f"[red]Unknown persona: {persona_name}. Available: {', '.join(PERSONAS.keys())}[/]")
            return ""
        old = state.get("persona")
        state["persona"] = None if persona_name == "default" else persona_name
        console.print(f"[green]Persona set to:[/] [bold]{persona_name}[/] — {PERSONAS[persona_name]}")
        await event_bus.publish("cli", "persona_change", {"persona": state.get("persona"), "old": old})
        return ""

    if cmd == "mode":
        if not args:
            current = state.get("mode", "auto")
            choices = sorted(MODES.keys()) + sorted(AGENTS.keys())
            console.print(Panel(
                f"[bold]Current mode:[/] [green]{current}[/]\n\n"
                + "\n".join(f"  [cyan]{i}[/] {c}" for i, c in enumerate(choices)),
                title="Mode Selector",
                border_style="cyan"
            ))
            try:
                pick = input("Enter number or name: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ""
            if pick.isdigit():
                idx = int(pick)
                if 0 <= idx < len(choices):
                    pick = choices[idx]
            if pick not in choices:
                console.print(f"[red]Invalid: {pick}[/]")
                return ""
            state["mode"] = pick
            console.print(f"[green]Switched to mode:[/] [bold]{pick}[/] — {MODES.get(pick, AGENTS.get(pick, [''])[0])}")
            return ""
        mode_name = args[0].lower()
        if mode_name not in MODES and mode_name not in AGENTS:
            console.print(f"[red]Unknown mode: {mode_name}[/]")
            return ""
            state["mode"] = mode_name
            console.print(f"[green]Switched to mode:[/] [bold]{mode_name}[/] — {MODES.get(mode_name, AGENTS.get(mode_name, [''])[0])}")
            await event_bus.publish("cli", "mode_change", {"mode": mode_name})
            return ""

    if cmd == "model":
        if not args:
            from orchestrator.providers import OPENCODE_CLI_ALIASES
            current = state.get("model", "auto")
            groups = [
                ("auto", ["auto"]),
            ]
            oc_free = sorted(a for a in WORKING_ALIASES if a.startswith("oc-") and ("free" in a or a in ("oc-big-pickle", "oc-hy3-free", "oc-mimo-free", "oc-north-mini-code")))
            oc_nv = sorted(a for a in WORKING_ALIASES if a.startswith("oc-") and a not in oc_free)
            ollama = sorted(a for a in WORKING_ALIASES if not a.startswith("oc-") and not a.startswith("or-"))
            or_ = sorted(a for a in WORKING_ALIASES if a.startswith("or-"))
            if oc_free:
                groups.append(("OpenCode Zen Free", oc_free))
            if oc_nv:
                groups.append(("OpenCode (NVIDIA-backed)", oc_nv))
            if or_:
                groups.append(("OmniRoute", or_))
            if ollama:
                groups.append(("Ollama", ollama))
            all_choices = []
            item_idx = 0
            for label, items in groups:
                all_choices.append((None, f"\n[bold]{label}[/]"))
                for item in items:
                    all_choices.append((item, f"  [cyan]{item_idx}[/] {item}"))
                    item_idx += 1
            lines = []
            for val, line in all_choices:
                lines.append(line)
            console.print(Panel(
                f"[bold]Current model:[/] [green]{current}[/]\n" + "\n".join(lines),
                title="Model Selector",
                border_style="cyan"
            ))
            try:
                pick = input("Enter number or name: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ""
            if pick.isdigit():
                idx = int(pick)
                items = [v for v, _ in all_choices if v is not None]
                if 0 <= idx < len(items):
                    pick = items[idx]
            if pick != "auto" and pick not in ALL_ALIASES:
                console.print(f"[red]Invalid: {pick}[/]")
                return ""
            state["model"] = pick
            console.print(f"[green]Model set to:[/] [bold]{pick}[/]")
            return ""
        model_name = args[0].lower()
        if model_name != "auto" and model_name not in ALL_ALIASES:
            console.print(f"[yellow]Unknown model '{model_name}'. Using 'auto'.[/]")
            model_name = "auto"
        state["model"] = model_name
        console.print(f"[green]Model set to:[/] [bold]{model_name}[/]")
        return ""

    if cmd == "models":
        from orchestrator.providers import OPENCODE_CLI_ALIASES
        table = Table(title="Available Models", box=box.ROUNDED)
        table.add_column("Alias", style="cyan")
        table.add_column("Resolved Model", style="white")
        table.add_column("Provider", style="green")
        for alias, resolved in sorted(ALL_ALIASES.items()):
            if alias in OPENCODE_CLI_ALIASES:
                provider = "opencode-cli"
            elif alias.startswith("or-"):
                provider = "omniroute"
            else:
                provider = "ollama"
            style = "bold" if alias in WORKING_ALIASES else "dim"
            table.add_row(alias, resolved, provider, style=style)
        console.print(table)
        console.print(f"[dim]Working models ({len(WORKING_ALIASES)}): {', '.join(WORKING_ALIASES)}[/]")
        return ""

    if cmd == "agent":
        if not args:
            console.print("[yellow]Usage: /agent <name> [query][/]")
            return ""
        name = args[0].lower()
        query = " ".join(args[1:]) if len(args) > 1 else ""
        if name not in AGENTS:
            console.print(f"[red]Unknown agent: {name}. Available: {', '.join(AGENTS.keys())}[/]")
            return ""
        label, desc = AGENTS[name]
        console.print(f"[bold]{label}[/] — {desc}")
        if not query:
            query = console.input("[cyan]Enter target/query: [/]")
        with console.status(f"[cyan]Running {label} agent..."):
            result = await run_cai_agent(name, query)
        print_md(result, title=f"{label} Agent")
        return ""

    if cmd in AGENTS:
        if cmd in ("scan", "exploit"):
            pass  # routed to dedicated handlers below
        else:
            query = " ".join(args) if args else console.input("[cyan]Enter target/query: [/]")
            label, desc = AGENTS[cmd]
            with console.status(f"[cyan]Running {label} agent..."):
                result = await run_cai_agent(cmd, query)
            print_md(result, title=f"{label} Agent")
            return ""

    if cmd == "team":
        if not args:
            console.print(f"[yellow]Usage: /team <workflow> [question]. Workflows: {', '.join(WORKFLOWS.keys())}[/]")
            return ""
        wf = args[0].lower()
        question = " ".join(args[1:]) if len(args) > 1 else console.input("[cyan]Enter question: [/]")
        if wf not in WORKFLOWS:
            console.print(f"[red]Unknown workflow: {wf}[/]")
            return ""
        wf_map = {"debate": teams_debate, "analyze": analyze, "code": code_gen, "execute": teams_execute, "plan": plan_task}
        fn = wf_map.get(wf)
        if not fn:
            console.print(f"[red]Workflow '{wf}' not implemented[/]")
            return ""
        with console.status(f"[cyan]Running {wf} workflow..."):
            result = await fn(question)
        if "synthesis" in result:
            print_md(result["synthesis"], title=f"Team {wf} — Synthesis")
        elif "response" in result:
            print_md(result["response"], title=f"Team {wf} — {result.get('model','?')} ({result.get('elapsed','?')}s)")
        elif "plan" in result:
            print_md(result["plan"], title=f"Team {wf} — Plan ({result.get('model','?')})")
        else:
            pp(result, title=f"Team {wf}")
        return ""

    if cmd == "scan":
        if not args:
            console.print("[yellow]Usage: /scan <target> [--ports N-M] [--nuclei-severity <sev>] [--no-proxy] [--direct][/]")
            return ""
        target = args[0]
        ports = "1-1000"
        sev = None
        use_proxy = True
        direct = False
        for i, a in enumerate(args[1:], 1):
            if a == "--ports" and i + 1 < len(args):
                ports = args[i + 1]
            elif a == "--nuclei-severity" and i + 1 < len(args):
                sev = args[i + 1]
            elif a == "--no-proxy":
                use_proxy = False
            elif a == "--direct":
                direct = True
                use_proxy = False
        await event_bus.publish("cli", "scan_start", {"target": target, "ports": ports, "proxy": use_proxy, "direct": direct})
        result = await cmd_scan(target, ports=ports, sev=sev, proxy=use_proxy, direct=direct)
        pp(result, title=f"Scan: {target}")
        return ""

    if cmd == "autonomous":
        if not args:
            console.print("[yellow]Usage: /autonomous <target> [--phases recon,scan,...][/]")
            return ""
        target = args[0]
        phases = None
        for i, a in enumerate(args[1:], 1):
            if a == "--phases" and i + 1 < len(args):
                phases = [p.strip() for p in args[i + 1].split(",")]

        await event_bus.publish("cli", "autonomous_start", {
            "target": target, "phases": phases,
            "persona": state.get("persona"),
        })
        with console.status(f"[cyan]Running autonomous engagement on {target}..."):
            result = await autonomous.handle(target, phases=phases)
        await event_bus.publish("cli", "autonomous_done", {"target": target, "status": "done"})
        pp(result, title=f"Autonomous: {target}")
        return ""

    if cmd == "agent-engage":
        if not args:
            console.print("[yellow]Usage: /agent-engage <target> [--persona X] [--phases r,s,...][/]")
            return ""
        target = args[0]
        persona = state.get("persona", "")
        phases = None
        for i, a in enumerate(args[1:], 1):
            if a == "--persona" and i + 1 < len(args):
                persona = args[i + 1]
            elif a == "--phases" and i + 1 < len(args):
                phases = [p.strip() for p in args[i + 1].split(",")]

        if not default_scope.check(target):
            console.print(f"[red]Target {target} not in allowed scope.[/]")
            return ""

        from orchestrator.agents.engage import run_agent_engage
        await event_bus.publish("cli", "agent_engage_start", {
            "target": target, "persona": persona, "phases": phases,
        })
        with console.status(f"[cyan]Running multi-agent engagement on {target} (persona={persona})..."):
            result = await run_agent_engage(target, persona=persona, phases=phases)
        await event_bus.publish("cli", "agent_engage_done", {"target": target, "status": "done"})
        pp(result, title=f"Agent Engage: {target}")
        return ""

    if cmd == "exploit":
        if not args:
            console.print("[yellow]Usage: /exploit <target> [--url <url>][/]")
            return ""
        target = args[0]
        url = None
        for i, a in enumerate(args[1:], 1):
            if a == "--url" and i + 1 < len(args):
                url = args[i + 1]
        result = await cmd_exploit(target, url=url)
        pp(result, title=f"Exploit: {target}")
        return ""

    if cmd == "stress":
        if not args:
            console.print("[yellow]Usage: /stress <target> [--method HTTP] [--threads 50] [--duration 60][/]")
            return ""
        target = args[0]
        method = "HTTP"
        threads = 50
        duration = 60
        use_tor = False
        for i, a in enumerate(args[1:], 1):
            if a == "--method" and i + 1 < len(args):
                method = args[i + 1]
            elif a == "--threads" and i + 1 < len(args):
                threads = int(args[i + 1])
            elif a == "--duration" and i + 1 < len(args):
                duration = int(args[i + 1])
            elif a == "--tor":
                use_tor = True
        result = await cmd_stress(target, method=method, threads=threads, duration=duration, use_tor=use_tor)
        pp(result, title=f"Stress: {method} → {target}")
        return ""

    if cmd == "cloak":
        if not args:
            console.print("[yellow]Usage: /cloak <url> [--screenshot] [--interact][/]")
            return ""
        url = args[0]
        action = "browse"
        if "--screenshot" in args:
            action = "screenshot"
        elif "--interact" in args:
            action = "interact"
        result = await cmd_cloak(url, action=action)
        if action == "browse" and "content" in result:
            print_md(result.get("content", "")[:3000], title=f"Cloak: {url}")
        elif action == "screenshot" and "screenshot" in result:
            console.print("[green]Screenshot captured[/]")
        else:
            pp(result, title=f"Cloak: {url}")
        return ""

    if cmd == "c2":
        if not args:
            console.print("[yellow]Usage: /c2 <target> [--payload pupy] [--command <cmd>] [--listen][/]")
            return ""
        target = args[0]
        payload = "pupy"
        command = None
        listen = False
        for i, a in enumerate(args[1:], 1):
            if a == "--payload" and i + 1 < len(args):
                payload = args[i + 1]
            elif a == "--command" and i + 1 < len(args):
                command = args[i + 1]
            elif a == "--listen":
                listen = True
        result = await cmd_c2(target, payload=payload, command=command, listen=listen)
        pp(result, title=f"C2: {target}")
        return ""

    if cmd == "phish":
        if not args:
            console.print("[yellow]Usage: /phish <target> [--engine gophish] [--template <name>][/]")
            return ""
        target = args[0]
        engine = "gophish"
        template = "default"
        for i, a in enumerate(args[1:], 1):
            if a == "--engine" and i + 1 < len(args):
                engine = args[i + 1]
            elif a == "--template" and i + 1 < len(args):
                template = args[i + 1]
        result = await cmd_phish(target, engine=engine, template=template)
        pp(result, title=f"Phish: {target}")
        return ""

    if cmd == "payloads":
        vector = args[0] if args else None
        count = 5
        for i, a in enumerate(args[1:], 1):
            if a == "--count" and i + 1 < len(args):
                count = int(args[i + 1])
        result = cmd_payloads(vector=vector, count=count)
        pp(result, title="PayloadsDB")
        return ""

    if cmd == "dashboard":
        await _show_dashboard(state)
        return ""

    if cmd == "engage":
        if not args:
            console.print("[yellow]Usage: /engage <target> [--phases p1,p2,...][/]")
            return ""
        target = args[0]
        phases = None
        for i, a in enumerate(args[1:], 1):
            if a == "--phases" and i + 1 < len(args):
                phases = [p.strip() for p in args[i + 1].split(",")]
        result = await _start_engage(target, phases)
        pp(result, title=f"Engagement: {target}")
        tid = grow.store_engagement_results(target, result)
        console.print(f"[dim]Growth: stored {tid} → /grow {target} to review[/]")
        return ""

    if cmd == "findings":
        target = args[0] if args else None
        if not target:
            console.print("[yellow]Usage: /findings <target>[/]")
            return ""
        result = await _get_findings(target)
        table = Table(title=f"Findings: {target}", box=box.ROUNDED)
        table.add_column("Phase", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="white")
        table.add_column("Target", style="green")
        for f in result.get("findings", []):
            table.add_row(f.get("phase", ""), f.get("type", ""),
                          f.get("severity", ""), f.get("description", "")[:60],
                          f.get("target", ""))
        console.print(table)
        return ""

    if cmd == "topology":
        target = args[0] if args else None
        if not target:
            console.print("[yellow]Usage: /topology <target>[/]")
            return ""
        result = await _get_findings(target)
        console.print(_render_topology(result.get("findings", []), target))
        return ""

    if cmd == "session":
        if not args:
            sessions = await _list_sessions()
            table = Table(title="Sessions", box=box.ROUNDED)
            table.add_column("ID", style="cyan")
            table.add_column("Target", style="white")
            table.add_column("Phase", style="yellow")
            table.add_column("Updated", style="green")
            for s in sessions:
                table.add_row(s.get("session_id", ""), s.get("target", ""),
                              s.get("current_phase", ""),
                              str(s.get("updated_at", "")))
            console.print(table)
            return ""
        sid = args[0]
        result = await _resume_session(sid)
        pp(result, title=f"Session: {sid}")
        return ""

    if cmd == "status":
        table = Table(title="Raphael 2.0 Status", box=box.ROUNDED)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Mode", state.get("mode", "single"))
        table.add_row("Model", state.get("model", "auto"))
        table.add_row("Working Models", str(len(WORKING_ALIASES)))
        table.add_row("Agents", str(len(AGENTS)))
        table.add_row("Proxy", "Available" if _proxy_available() else "Unavailable")
        stats = cost_tracker_stats()
        table.add_row("API Calls", str(stats["total_calls"]))
        table.add_row("Total Tokens", str(stats["total_tokens"]))
        console.print(table)
        console.print()
        console.print("[bold cyan]Docker Services:[/]")
        services = _service_status()
        if isinstance(services, dict) and "error" in services:
            console.print(f"[red]{services['error']}[/]")
        else:
            for name, status in services.items():
                icon = "[green]✓[/]" if "Up" in status else "[dim]✗[/]"
                console.print(f"  {icon} {name}: {status}")
        return ""

    if cmd == "proxy":
        from orchestrator.proxy_guard import ProxyGuard
        subcmd = args[0] if args else "status"

        if subcmd == "status":
            pg = ProxyGuard()
            s = pg.status()
            ext_ip = pg._get_exit_ip() or "unknown"
            table = Table(title="Proxy Status", box=box.ROUNDED)
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Active", str(s.get("active", False)))
            table.add_row("Strategy", s.get("strategy", "none"))
            table.add_row("Exit IP", ext_ip)
            table.add_row("Circuit ID", (s.get("circuit_id") or "none")[:16])
            table.add_row("Tor Running", str(s.get("tor_running", False)))
            table.add_row("WireGuard", str(pg._check_wireguard(silent=True)))
            table.add_row("ProtonVPN", str(pg._check_protonvpn(silent=True)))
            table.add_row("VPN Passive", str(pg._check_vpn_passive(silent=True)))
            console.print(table)

        elif subcmd == "new-circuit":
            with console.status("[cyan]Requesting new Tor circuit..."):
                pg = ProxyGuard()
                cid = pg.new_circuit()
            console.print(f"[green]New circuit:[/] {cid}")
            console.print(f"[green]Exit IP:[/] {pg.status().get('exit_ip', '?')}")

        elif subcmd == "verify":
            with console.status("[cyan]Verifying proxy chain..."):
                pg = ProxyGuard()
                try:
                    pg.verify()
                    console.print("[green]✓ Proxy verification passed[/]")
                except Exception as e:
                    console.print(f"[red]✗ Proxy verification failed: {e}[/]")

        elif subcmd == "start":
            console.print("[yellow]To start Tor: docker start raphael-20-tor-proxy-1[/]")
            console.print("[yellow]To start WireGuard: sudo wg-quick up /etc/wireguard/wg0.conf[/]")
            console.print("[yellow]To start ProtonVPN: protonvpn-cli connect[/]")
            console.print("[yellow]To start OpenVPN: /vpn connect <config.ovpn>[/]")

        else:
            console.print(f"[yellow]Usage: /proxy [status|verify|new-circuit|start][/]")
        return ""

    if cmd == "vpn":
        from orchestrator.proxy_guard import ProxyGuard
        subcmd = args[0] if args else "status"
        pg = ProxyGuard()

        if subcmd == "status":
            s = pg.openvpn_status()
            table = Table(title="OpenVPN Status", box=box.ROUNDED)
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Connected", str(s.get("connected", False)))
            table.add_row("Interface", s.get("interface") or "—")
            table.add_row("IP", s.get("ip") or "—")
            table.add_row("Config", s.get("config") or "—")
            console.print(table)

        elif subcmd == "connect":
            config_path = args[1] if len(args) > 1 else None
            if not config_path:
                console.print("[yellow]Usage: /vpn connect <config.ovpn> [--auth-user-pass <file>][/]")
                return ""
            auth = None
            for i, a in enumerate(args[2:], 2):
                if a == "--auth-user-pass" and i + 1 < len(args):
                    auth = args[i + 1]
            if not os.path.exists(config_path):
                console.print(f"[red]Config not found: {config_path}[/]")
                return ""
            with console.status(f"[cyan]Connecting OpenVPN: {config_path}..."):
                ok = pg.openvpn_connect(config_path, auth_user_pass=auth)
            if ok:
                console.print("[green]✓ OpenVPN starting[/]")
                # Wait a few seconds for connection
                import time
                time.sleep(4)
                s = pg.openvpn_status()
                console.print(f"[green]Interface: {s.get('interface','?')} | IP: {s.get('ip','?')}[/]")
            else:
                console.print("[red]✗ OpenVPN failed to start[/]")

        elif subcmd == "disconnect":
            with console.status("[cyan]Stopping OpenVPN..."):
                ok = pg.openvpn_disconnect()
            if ok:
                console.print("[green]✓ OpenVPN disconnected[/]")
            else:
                console.print("[yellow]No OpenVPN process found[/]")

        elif subcmd == "htb":
            console.print("[yellow]Usage: /vpn htb <path/to/htb.ovpn>[/]")
            console.print("[yellow]Downloads and connects to HTB VPN automatically.[/]")

        else:
            console.print("[yellow]Usage: /vpn [status|connect|disconnect][/]")
            console.print("[yellow]  /vpn connect <config.ovpn> [--auth-user-pass <file>][/]")
            console.print("[yellow]  /vpn disconnect[/]")
            console.print("[yellow]  /vpn status[/]")
        return ""

    if cmd == "verify":
        from orchestrator.brain.phases import PHASE_EXECUTORS
        with console.status("[cyan]Verifying all Raphael systems..."):
            report = await _verify_all()
        overall = all(
            v.get("pass", False) for v in report.values()
            if isinstance(v, dict)
        )
        icon = "[green]✓ ALL SYSTEMS NOMINAL[/]" if overall else "[red]✗ SOME CHECKS FAILED[/]"
        console.print(Panel(icon, title="Verify Result", border_style="green" if overall else "red"))

        for category, data in report.items():
            if not isinstance(data, dict):
                continue
            passed = data.get("pass", False)
            cat_icon = "[green]✓[/]" if passed else "[red]✗[/]"
            summary = ""
            if category == "containers":
                summary = f"({data.get('up',0)}/{data.get('total',0)} up)"
            elif category == "services":
                summary = f"({data.get('up',0)}/{data.get('total',0)} responsive)"
            elif category == "kali_tools":
                summary = f"({data.get('tools_count',0)} tools, health: {data.get('health','?')})"
            elif category == "proxy":
                summary = "(Tor port 9050)" if data.get("pass") else "(not reachable)"
            elif category == "phases":
                m = data.get("missing", [])
                summary = f"({data.get('registered',0)}/{data.get('expected',0)} phases"
                if m:
                    summary += f", missing: {','.join(m)}"
                summary += ")"
            console.print(f"  {cat_icon} [bold]{category}[/] {summary}")

            if not passed and "detail" in data:
                for name, status in data["detail"].items():
                    if isinstance(status, dict) and not status.get("ok", True):
                        err = status.get("error", status.get("status", "unknown"))
                        console.print(f"       [dim]{name}:[/] [red]{err}[/]")
        return ""

    if cmd == "start":
        _start_services()
        return ""

    if cmd == "stop":
        _stop_services()
        return ""

    if cmd == "bloodhound":
        query_name = args[0] if args else "find_da"
        valid_queries = ["find_da", "all_users", "all_computers", "admin_sessions", "constrained_delegation", "kerberoastable"]
        if query_name not in valid_queries:
            console.print(f"[yellow]Available queries: {', '.join(valid_queries)}[/]")
            return ""
        with console.status(f"[cyan]Running BloodHound query: {query_name}..."):
            result = _run_bloodhound_query(query_name)
        pp(json.loads(result), title=f"BloodHound — {query_name}")
        return ""

    if cmd == "strix":
        if not args:
            console.print("[yellow]Usage: /strix <target>[/]")
            return ""
        target = args[0]
        with console.status(f"[cyan]Running Strix against {target}..."):
            result = await _run_strix(target)
        print_md(result, title=f"Strix: {target}")
        return ""

    if cmd == "grow":
        target = args[0] if args else None
        stats = grow.stats()
        table = Table(title="Growth Knowledge Base", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="white")
        for k, v in stats.items():
            table.add_row(k.replace("_", " ").title(), str(v))
        console.print(table)
        if target:
            targets = grow.get_target_summary(target)
            if targets:
                t = targets[0]
                console.print(Panel(f"[bold]Target:[/] {t['host']}  [dim]({t['id']})[/]\n"
                                    f"[bold]Tags:[/] {t['tags'] or 'none'}\n"
                                    f"[bold]Notes:[/] {t['notes'] or 'none'}",
                                    title=f"Target: {target}", border_style="cyan"))
                findings_table = Table(title=f"Findings for {target}", box=box.ROUNDED)
                findings_table.add_column("Phase", style="cyan")
                findings_table.add_column("Type", style="yellow")
                findings_table.add_column("Severity", style="red")
                findings_table.add_column("Description", style="white")
                techs = grow.get_techniques(min_confidence=0.0)
                for tech in techs[:10]:
                    findings_table.add_row(tech["category"], tech["technique"],
                                           f'{tech["confidence"]:.0%}', tech["description"][:50])
                console.print(findings_table)
        else:
            recent = grow.get_target_summary()
            if recent:
                t2 = Table(title="Recent Targets", box=box.ROUNDED)
                t2.add_column("ID", style="cyan")
                t2.add_column("Host", style="white")
                t2.add_column("Last Seen", style="green")
                for r in recent:
                    t2.add_row(r["id"], r["host"], time.strftime("%H:%M:%S", time.localtime(r["last_seen"])))
                console.print(t2)
        return ""

    if cmd == "patterns":
        ptype = args[0] if args else None
        patterns = grow.get_patterns(pattern_type=ptype)
        table = Table(title=f"{'Patterns' if not ptype else f'Patterns: {ptype}'}", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Source", style="white")
        table.add_column("Uses", style="green")
        table.add_column("Effectiveness", style="yellow")
        table.add_column("Data", style="white")
        for p in patterns[:15]:
            data_str = json.dumps(p["data"], default=str)[:60]
            table.add_row(p["type"], p["source"] or "?", str(p["uses"]), f'{p["effectiveness"]:.0%}', data_str)
        console.print(table)
        return ""

    if cmd == "techniques":
        min_conf = float(args[0]) if args and args[0].replace(".", "").isdigit() else 0.0
        techs = grow.get_techniques(min_confidence=min_conf)
        table = Table(title=f"Techniques (confidence >= {min_conf:.0%})", box=box.ROUNDED)
        table.add_column("Technique", style="cyan")
        table.add_column("Category", style="yellow")
        table.add_column("S/F", style="green")
        table.add_column("Confidence", style="red")
        table.add_column("Last Used", style="white")
        for t in techs[:20]:
            table.add_row(t["technique"], t["category"],
                          f'{t["successes"]}/{t["failures"]}',
                          f'{t["confidence"]:.0%}',
                          time.strftime("%H:%M:%S", time.localtime(t["last_used"])) if t["last_used"] else "never")
        console.print(table)
        return ""

    if cmd == "websearch" or cmd == "web":
        if not args:
            console.print("[yellow]Usage: /websearch <query>[/]")
            return ""
        query = " ".join(args)
        from orchestrator.web_tools import web_search, format_search_results
        with console.status(f"[cyan]Searching: {query}..."):
            results = await web_search(query)
        output = format_search_results(results)
        print_md(output, title=f"Web Search: {query}")
        return ""

    if cmd == "fetch":
        if not args:
            console.print("[yellow]Usage: /fetch <url>[/]")
            return ""
        url = args[0]
        from orchestrator.web_tools import fetch_url, format_fetch_result
        with console.status(f"[cyan]Fetching: {url}..."):
            result = await fetch_url(url)
        output = format_fetch_result(result)
        print_md(output, title=f"Fetch: {url}")
        return ""

    if cmd == "rsi-config":
        state.setdefault("rsi_rounds", 2)
        state.setdefault("rsi_rounds_limit", 5)
        if args:
            for i, a in enumerate(args):
                if a == "--rounds" and i + 1 < len(args):
                    state["rsi_rounds"] = int(args[i + 1])
                elif a == "--rounds-limit" and i + 1 < len(args):
                    state["rsi_rounds_limit"] = int(args[i + 1])
                elif a == "--models" and i + 1 < len(args):
                    models_dict = {}
                    for pair in args[i + 1].split(","):
                        if "=" in pair:
                            role, alias = pair.split("=", 1)
                            models_dict[role.strip()] = alias.strip()
                    if models_dict:
                        state["rsi_models"] = models_dict
        console.print(f"[green]RSI config: rounds={state['rsi_rounds']}, limit={state['rsi_rounds_limit']}, models={state.get('rsi_models', 'default')}[/]")
        return ""

    if cmd == "debate-config":
        state.setdefault("debate_rounds", 3)
        if args:
            for i, a in enumerate(args):
                if a == "--rounds" and i + 1 < len(args):
                    state["debate_rounds"] = int(args[i + 1])
                elif a == "--models" and i + 1 < len(args):
                    state["debate_models"] = [m.strip() for m in args[i + 1].split(",")]
        console.print(f"[green]Debate config: rounds={state['debate_rounds']}, models={state.get('debate_models', 'default (w12,w13)')}[/]")
        return ""

    if cmd == "community-config":
        state.setdefault("community_rounds", 2)
        if args:
            for i, a in enumerate(args):
                if a == "--rounds" and i + 1 < len(args):
                    state["community_rounds"] = int(args[i + 1])
                elif a == "--models" and i + 1 < len(args):
                    state["community_models"] = [m.strip() for m in args[i + 1].split(",")]
        console.print(f"[green]Community config: rounds={state['community_rounds']}, models={state.get('community_models', 'default (w12,w13,w480b,m3)')}[/]")
        return ""

    if cmd == "validate":
        if not args:
            console.print("[yellow]Usage: /validate <target> [--results <path>][/]")
            return ""
        target = args[0]
        results_path = None
        for i, a in enumerate(args[1:], 1):
            if a == "--results" and i + 1 < len(args):
                results_path = args[i + 1]
        if not results_path:
            results_path = f"raphael_{target}_results.json"
        if not os.path.exists(results_path):
            console.print(f"[red]No results found at {results_path}[/]")
            return ""
        with open(results_path) as f:
            results = json.load(f)
        from orchestrator.validation.exploit_validator import ExploitValidator
        validator = ExploitValidator()
        all_findings = []
        for phase_name, phase_data in results.get("phases", {}).items():
            for f in phase_data.get("findings", []):
                if isinstance(f, dict):
                    all_findings.append(f)
        validated = asyncio.run(validator.validate_findings(all_findings, target))
        results["validation"] = {
            "total_raw": len(all_findings),
            "total_validated": validator.get_stats()["validated"],
            "rejected": validator.get_stats()["rejected"],
            "uncertain": validator.get_stats()["uncertain"],
            "findings": [vf.to_dict() for vf in validated],
        }
        output = results_path.replace(".json", "_validated.json")
        with open(output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        from orchestrator.validation.false_positive_reducer import FalsePositiveReducer
        reducer = FalsePositiveReducer()
        accepted, rejected = reducer.reduce(all_findings, target)
        console.print(f"[green]Validation complete:[/]")
        console.print(f"  Raw: {validator.get_stats()['total']}")
        console.print(f"  Validated: {validator.get_stats()['validated']}")
        console.print(f"  Rejected (FP): {len(rejected)}")
        console.print(f"  FP reducer: {len(accepted)} accepted")
        console.print(f"[dim]Results saved to {output}[/]")
        return ""

    if cmd == "fp-reduce" or cmd == "fpreduce":
        if not args:
            console.print("[yellow]Usage: /fp-reduce <target> [--results <path>][/]")
            return ""
        from orchestrator.validation.false_positive_reducer import FalsePositiveReducer
        reducer = FalsePositiveReducer()
        target = args[0]
        results_path = None
        for i, a in enumerate(args[1:], 1):
            if a == "--results" and i + 1 < len(args):
                results_path = args[i + 1]
        if not results_path:
            results_path = f"raphael_{target}_results.json"
        if not os.path.exists(results_path):
            console.print(f"[red]No results found at {results_path}[/]")
            return ""
        with open(results_path) as f:
            results = json.load(f)
        all_findings = []
        for phase_name, phase_data in results.get("phases", {}).items():
            for f in phase_data.get("findings", []):
                if isinstance(f, dict):
                    all_findings.append(f)
        accepted, rejected = reducer.reduce(all_findings, target)
        console.print(f"[green]FP Reduction complete:[/]")
        console.print(f"  Total: {len(all_findings)}")
        console.print(f"  Accepted: {len(accepted)}")
        console.print(f"  Rejected: {len(rejected)}")
        return ""

    if cmd == "compliance":
        if not args:
            console.print("[yellow]Usage: /compliance <target> [--results <path>] [--domain <domain>][/]")
            return ""
        target = args[0]
        results_path = None
        domain = target
        for i, a in enumerate(args[1:], 1):
            if a == "--results" and i + 1 < len(args):
                results_path = args[i + 1]
            elif a == "--domain" and i + 1 < len(args):
                domain = args[i + 1]
        if not results_path:
            results_path = f"raphael_{target}_results.json"
        if not os.path.exists(results_path):
            console.print(f"[red]No results found at {results_path}[/]")
            return ""
        with open(results_path) as f:
            results = json.load(f)
        from orchestrator.compliance.mapper import ComplianceMapper
        all_findings = []
        for phase_name, phase_data in results.get("phases", {}).items():
            for f in phase_data.get("findings", []):
                if isinstance(f, dict):
                    all_findings.append(f)
        mapper = ComplianceMapper({"name": target, "domain": domain, "type": "web_application"})
        compliance_report = mapper.map_findings(all_findings)
        output = f"{target}_compliance_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output, "w") as f:
            json.dump(compliance_report, f, indent=2)
        breakdown = compliance_report.get("regulation_breakdown", {})
        console.print(f"[green]Compliance report generated: {output}[/]")
        console.print(f"\n[bold]Regulation Impact:[/]")
        for reg, data in sorted(breakdown.items()):
            console.print(f"  {reg}: {data.get('total_controls_affected', 0)} controls affected "
                          f"(C:{data.get('critical_findings', 0)} "
                          f"H:{data.get('high_findings', 0)} "
                          f"M:{data.get('medium_findings', 0)})")
        ai_act = compliance_report.get("ai_act_assessment", {})
        console.print(f"\n[bold]EU AI Act Risk:[/] {ai_act.get('risk_category', 'unknown')}")
        return ""

    if cmd == "ai-security" or cmd == "aisecurity":
        from orchestrator.ai_security.tsinghua_scanner import TsinghuaScanner
        with console.status("[cyan]Running AI agent security scan (Tsinghua 5 vectors)..."):
            scanner = TsinghuaScanner()
            report = asyncio.run(scanner.run_full_battery())
        output = f"ai_security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green]AI Security scan complete: {output}[/]")
        if report.get("vulnerable"):
            console.print(f"[red]  VULNERABLE: {report['summary']['vulnerable_tests']} tests passed[/]")
        else:
            console.print(f"[green]  No vulnerabilities found[/]")
        console.print(f"  Vectors tested: {report['summary']['vectors_tested']}")
        console.print(f"  Vectors vulnerable: {report['summary']['vectors_vulnerable']}")
        for r in report.get("results", []):
            icon = "[red]✗[/]" if r.get("success") else "[green]✓[/]"
            console.print(f"  {icon} {r.get('vector')}: {r.get('test_name')} "
                          f"({'VULNERABLE' if r.get('success') else 'OK'}) "
                          f"[{r.get('severity')}]")
        return ""

    if cmd == "benchmark":
        targets_dir = "benchmarks/targets"
        for i, a in enumerate(args):
            if a == "--targets-dir" and i + 1 < len(args):
                targets_dir = args[i + 1]
        with console.status("[cyan]Running full-lifecycle benchmark..."):
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from benchmarks.full_lifecycle_benchmark import BenchmarkRunner
            runner = BenchmarkRunner(targets_dir=targets_dir)
            report = asyncio.run(runner.run_all())
        output = f"benchmark_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"[green]Benchmark complete: {output}[/]")
        if "error" in report:
            console.print(f"[red]  Error: {report['error']}[/]")
        else:
            console.print(f"  Targets: {report.get('total_targets', 0)}")
            console.print(f"  Passed: {report.get('passed', 0)}")
            console.print(f"  Failed: {report.get('failed', 0)}")
            console.print(f"  Pass rate: {report.get('pass_rate', 0) * 100:.0f}%")
            for r in report.get("results", []):
                icon = "[green]✓[/]" if r.get("success") else "[red]✗[/]"
                console.print(f"  {icon} {r.get('target')} ({r.get('total_time', 0):.0f}s, "
                              f"{r.get('total_findings', 0)} findings)")
        return ""

    console.print(f"[red]Unknown command: /{cmd}[/]")
    console.print("[dim]Type /help for available commands[/]")
    return ""


RAPHAEL_DIR = Path(__file__).resolve().parent


SERVICE_ENDPOINTS = {
    "brain API":       "http://localhost:3700/v1/health",
    "cai-service":     "http://localhost:3201/health",
    "sword pipeline":  "http://localhost:3600/health",
    "c2-server":       "http://localhost:3501/health",
    "phishing":        "http://localhost:3502/health",
    "recon-pipeline":  "http://localhost:3503/health",
    "mhddos":          "http://localhost:3301/health",
    "cloak-service":   "http://localhost:3401/health",
    "neo4j":           "http://localhost:7474",
    "caido":           "http://localhost:48080",
    "freellmapi":      "http://localhost:3001/health",
    "kali-tools":      "http://localhost:3800/health",
}


async def _verify_all() -> dict:
    """Check every Raphael component and return pass/fail per group."""
    import httpx
    results = {}

    # ── Docker containers ──
    services = _service_status()
    containers = {n: "Up" in s for n, s in services.items()}
    results["containers"] = {
        "pass": all(containers.values()) if containers else False,
        "total": len(containers),
        "up": sum(1 for v in containers.values() if v),
        "detail": containers,
    }

    # ── HTTP service endpoints ──
    svc_passes = 0
    svc_total = 0
    svc_detail = {}
    async with httpx.AsyncClient(timeout=5) as cl:
        for name, url in SERVICE_ENDPOINTS.items():
            svc_total += 1
            try:
                r = await cl.get(url)
                ok = r.status_code < 500
                svc_detail[name] = {"ok": ok, "status": r.status_code}
                if ok:
                    svc_passes += 1
            except Exception as e:
                svc_detail[name] = {"ok": False, "error": str(e)[:60]}
    results["services"] = {
        "pass": svc_passes == svc_total,
        "total": svc_total,
        "up": svc_passes,
        "detail": svc_detail,
    }

    # ── kali-tools inventory ──
    try:
        from orchestrator.kali_tools_client import kali
        tools = await kali.tools_list()
        health = await kali.health()
        results["kali_tools"] = {
            "pass": health.get("status") == "ok" and len(tools) > 0,
            "tools_count": len(tools),
            "health": health.get("status", "unknown"),
        }
    except Exception as e:
        results["kali_tools"] = {"pass": False, "error": str(e)[:80]}

    # ── Tor / proxy ──
    results["proxy"] = {
        "pass": _proxy_available(),
        "tor_port_9050": _proxy_available(),
    }

    # ── Phase executors ──
    try:
        from orchestrator.brain.phases import PHASE_EXECUTORS
        expected = {"recon", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"}
        registered = set(PHASE_EXECUTORS.keys())
        results["phases"] = {
            "pass": expected.issubset(registered),
            "registered": len(registered),
            "expected": len(expected),
            "missing": sorted(expected - registered),
        }
    except Exception as e:
        results["phases"] = {"pass": False, "error": str(e)[:80]}

    return results


def _proxy_available():
    """Quick proxy availability check."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 9050))
        s.close()
        return True
    except Exception:
        return False


def _service_status() -> dict:
    """Get docker service statuses."""
    import subprocess
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=10,
            cwd=RAPHAEL_DIR
        )
        statuses = {}
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t", 1)
            statuses[parts[0]] = parts[1] if len(parts) > 1 else "running"
        return statuses
    except Exception as e:
        return {"error": str(e)}


def _compose_cmd(action: str) -> dict:
    """Run docker compose command, return result dict."""
    import subprocess
    try:
        compose_cmd = "docker-compose" if subprocess.run(["which", "docker-compose"], capture_output=True).returncode == 0 else "docker compose"
        r = subprocess.run(
            compose_cmd.split() + [action],
            capture_output=True, text=True, timeout=120,
            cwd=RAPHAEL_DIR
        )
        return {"success": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _start_services():
    """Start all Docker Compose services."""
    console.print("[cyan]Starting Raphael services...[/]")
    result = _compose_cmd("up -d")
    if result["success"]:
        console.print("[green]✓ Services started[/]")
    elif "already" in (result.get("stderr") or "").lower():
        console.print("[yellow]○ Services already running[/]")
    else:
        console.print(f"[red]✗ Docker compose error: {result.get('stderr', result.get('error', 'unknown'))}[/]")
    statuses = _service_status()
    for name, status in statuses.items():
        icon = "[green]✓[/]" if "Up" in status else "[red]✗[/]"
        console.print(f"  {icon} {name}: {status}")


def _stop_services():
    """Stop all Docker Compose services."""
    console.print("[yellow]Stopping Raphael services...[/]")
    result = _compose_cmd("down")
    if result["success"]:
        console.print("[green]✓ Services stopped[/]")
    else:
        console.print(f"[red]✗ Docker compose error: {result.get('stderr', result.get('error', 'unknown'))}[/]")


def _run_bloodhound_query(query_name: str = "find_da") -> str:
    """Run BloodHound query via c2-server API."""
    import httpx
    try:
        r = httpx.post(
            "http://localhost:3501/bloodhound/query",
            json={"query_name": query_name},
            timeout=10
        )
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"error": f"Cannot reach BloodHound API: {e}"})


async def _run_strix(target: str) -> str:
    """Run Strix penetration test."""
    import subprocess
    try:
        r = subprocess.run(
            ["strix", "-t", target, "-m", "quick"],
            capture_output=True, text=True, timeout=300
        )
        out = r.stdout.strip()
        err = r.stderr.strip()
        if r.returncode != 0:
            return f"[red]Strix error (code {r.returncode}):[/]\n{err[:2000]}"
        return f"[green]Strix scan complete:[/]\n{out[:3000]}" if out else "[yellow]No output from Strix[/]"
    except FileNotFoundError:
        return "[red]Strix not installed. Run: pipx install /tmp/strix[/]"
    except subprocess.TimeoutExpired:
        return "[red]Strix timed out (300s limit)[/]"
    except Exception as e:
        return f"[red]Strix error: {e}[/]"


async def _show_dashboard(state: dict):
    api = os.getenv("BRAIN_API", "http://localhost:3700")
    import httpx

    async def _fetch():
        try:
            async with httpx.AsyncClient(timeout=5) as cl:
                r = await cl.get(f"{api}/v1/cli/status")
                return r.json()
        except Exception:
            return {"engagements": [], "agents": [], "models_tracked": 0, "chain_steps": 0}

    data = await _fetch()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="engagements"),
        Layout(name="agents"),
    )

    def render_engagements(data: dict) -> Table:
        table = Table(title="Active Engagements", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Phase", style="yellow")
        for eng in data.get("engagements", []):
            table.add_row(eng.get("session_id", "?")[:8],
                          eng.get("target", "?"),
                          eng.get("current_phase", "?"))
        return table

    def render_agents(data: dict) -> Table:
        table = Table(title="C2 Agents", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Host", style="white")
        table.add_column("OS", style="yellow")
        table.add_column("Status", style="green")
        for a in data.get("agents", []):
            table.add_row(a.get("id", "?")[:8], a.get("hostname", "?"),
                          a.get("os", "?"), a.get("status", "?"))
        return table

    header_panel = Panel(f"[bold cyan]Raphael 2.0 — Dashboard[/]\n"
                         f"Models: {data.get('models_tracked', 0)}  "
                         f"Chain steps: {data.get('chain_steps', 0)}  "
                         f"Engagements: {len(data.get('engagements', []))}  "
                         f"Agents: {len(data.get('agents', []))}")

    footer_panel = Panel("[dim]Press Ctrl+C to exit dashboard[/]")

    console.clear()
    try:
        with Live(layout, refresh_per_second=1, screen=True) as live:
            while True:
                data = await _fetch()
                layout["header"].update(header_panel)
                layout["engagements"].update(render_engagements(data))
                layout["agents"].update(render_agents(data))
                layout["footer"].update(footer_panel)
                await asyncio.sleep(2)
    except KeyboardInterrupt:
        pass

    console.print("[dim]Dashboard closed[/]")


async def _start_engage(target: str, phases: list[str] = None) -> dict:
    api = os.getenv("BRAIN_API", "http://localhost:3700")
    import httpx
    payload = {"target": target}
    if phases:
        payload["phases"] = phases
    try:
        async with httpx.AsyncClient(timeout=600) as cl:
            r = await cl.post(f"{api}/v1/engage/start", json=payload)
            return r.json()
    except Exception as e:
        return {"error": str(e)}


async def _get_findings(target: str) -> dict:
    api = os.getenv("BRAIN_API", "http://localhost:3700")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as cl:
            r = await cl.get(f"{api}/v1/brain/memory", params={"target": target, "limit": 100})
            return r.json()
    except Exception:
        return {"findings": []}


def _render_topology(findings: list[dict], target: str) -> str:
    lines = []
    lines.append(f"┌─ {target}")
    ports = {str(f.get("port", "?")): f for f in findings if f.get("port")}
    vulns = [f for f in findings if f.get("severity") in ("critical", "high")]
    for port, f in ports.items():
        sev = f.get("severity", "info")
        flag = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🔵"}.get(sev, "⚪")
        svc = f.get("service", "") or f.get("protocol", "")
        lines.append(f"│  {flag} Port {port}  {svc}")
    for v in vulns[:5]:
        sev = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🔵"}.get(v.get("severity", ""), "⚪")
        desc = v.get("description", v.get("type", ""))[:60]
        lines.append(f"│    {sev} {desc}")
    lines.append("└─")
    return "\n".join(lines)


async def _list_sessions() -> list[dict]:
    api = os.getenv("BRAIN_API", "http://localhost:3700")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5) as cl:
            r = await cl.get(f"{api}/v1/cli/status")
            data = r.json()
            return data.get("engagements", [])
    except Exception:
        return []


async def _resume_session(session_id: str) -> dict:
    api = os.getenv("BRAIN_API", "http://localhost:3700")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as cl:
            r = await cl.get(f"{api}/v1/session/{session_id}")
            return r.json()
    except Exception as e:
        return {"error": str(e)}


def main() -> None:
    """Synchronous entry point for CLI."""
    asyncio.run(_main())


async def _main() -> None:
    """Original async main logic."""
    console.clear()
    console.print(r"""
[bold cyan]
    ██████  █████  ██████  ██   ██  █████  ███████ ██
   ██      ██   ██ ██   ██ ██   ██ ██   ██ ██      ██
   ██      ███████ ██████  ███████ ███████ █████   ██
   ██      ██   ██ ██      ██   ██ ██   ██ ██
    ██████ ██   ██ ██      ██   ██ ██   ██ ███████ ██
[/]
[dim]v2.0 — Autonomous AI Security Platform[/]
[dim]Type /help for commands, /exit to quit[/]
""")

    # _warn_weak_defaults()  # disabled for uncensored mode

    state = {"mode": "single", "model": "auto", "persona": None}

    _start_services()

    event_bus.start()
    console.print("[dim]Event bus started.[/]")

    console.print()
    console.print("[dim]All services should be available now. Type /help for commands.[/]")

    history = FileHistory(str(HISTORY_PATH)) if HISTORY_PATH.parent.exists() else None
    session = PromptSession(history=history)

    while True:
        try:
            p_tag = f"/{state['persona']}" if state.get("persona") else ""
            prompt_text = f"raphael [{state['mode']}{p_tag}] > "
            user_input = await session.prompt_async(prompt_text, style=PROMPT_STYLE)
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        user_input = user_input.strip()
        if not user_input:
            continue

        if user_input.startswith("/"):
            parts = user_input[1:].split()
            cmd = parts[0].lower()
            args = parts[1:]
            try:
                await handle_command(cmd, args, state)
            except Exception as e:
                console.print(f"[red]Command error: {e}[/]")
                if "--debug" in sys.argv:
                    console.print(traceback.format_exc())
        else:
            with console.status(f"[cyan]Thinking... [{state['mode']}/{state.get('model','auto')}]"):
                try:
                    result = await call_llm(state["mode"], user_input, state.get("model", "auto"), state)
                except Exception as e:
                    result = f"[red]Error: {e}[/]"
                    if "--debug" in sys.argv:
                        console.print(traceback.format_exc())
            print_md(result, title=f"{state['mode'].upper()} Response")


if __name__ == "__main__":
    main()
