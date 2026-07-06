#!/usr/bin/env python3
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

atexit.register(_forensic_wipe_on_exit)

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

[bold]Commands:[/]
  [green]/mode[/] [name]         Show/switch operation mode
  [green]/agent[/] [name] [q]   Run a CAI agent by name
  [green]/model[/] [name]       Set model alias (auto, w12, w13, deepseek, etc.)
  [green]/team[/] [wf] [q]      Run team workflow (debate, analyze, code, execute, plan)
  [green]/scan[/] <target>      Scan target [--ports N-M] [--nuclei-severity <sev>]
  [green]/exploit[/] <target>   Exploit target [--url <url>]
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
  [green]/status[/]             Show system & service status
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


async def call_llm(mode: str, prompt: str) -> str:
    """Route a prompt through the orchestrator by mode."""
    try:
        if mode in ("recon", "scan", "exploit", "defend", "forensic", "oracle", "chat", "audit"):
            result = await call_model(mode, [{"role": "user", "content": prompt}])
            return result or "[No response]"
        elif mode == "debate":
            result = await debate.handle(prompt)
            return result.get("final", result.get("synthesis", json.dumps(result, indent=2)))
        elif mode == "community":
            result = await community.handle(prompt)
            return result.get("final", result.get("synthesis", json.dumps(result, indent=2)))
        elif mode == "rsi":
            result = await rsi.handle(prompt)
            return result.get("unified_plan", json.dumps(result, indent=2))
        elif mode == "deep_research":
            result = await deep_research.handle(prompt)
            return result.get("final", result.get("rsi_output", json.dumps(result, indent=2)))
        elif mode == "postmortem":
            result = await postmortem.handle(prompt)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        elif mode == "autonomous":
            result = await autonomous.handle(prompt)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        else:
            result = await call_model(mode, [{"role": "user", "content": prompt}])
            return result or "[No response]"
    except Exception as e:
        return f"[Error: {e}]"


async def run_cai_agent(agent: str, target: str) -> str:
    """Run a dedicated CAI agent (recon, scan, etc.)"""
    try:
        from orchestrator.modes import scan
        if agent == "scan":
            result = await scan.handle(target)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        payload = {"target": target, "extra_params": {"context": ""}}
        prompt = json.dumps(payload)
        system = f"You are the {agent} security agent. Respond with actionable security findings based on the target information provided."
        result = await call_model("auto", [{"role": "user", "content": prompt}], system_override=system)
        return result or "[No response]"
    except Exception as e:
        return f"[Error: {e}]"


async def cmd_scan(target: str, ports="1-1000", sev=None, proxy=True):
    """Run scan mode."""
    with console.status(f"[cyan]Scanning {target}..."):
        result = await scan_mode.handle(target, ports=ports, nuclei_severity=sev, use_proxy=proxy)
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

    if cmd == "mode":
        if not args:
            console.print(Panel(f"[bold]Current mode:[/] [green]{state['mode']}[/]\n\n[dim]Available:[/] {' | '.join(sorted(MODES.keys()))}", title="Mode", border_style="cyan"))
            return ""
        mode_name = args[0].lower()
        if mode_name not in MODES and mode_name not in AGENTS:
            console.print(f"[red]Unknown mode: {mode_name}[/]")
            return ""
        state["mode"] = mode_name
        console.print(f"[green]Switched to mode:[/] [bold]{mode_name}[/] — {MODES.get(mode_name, AGENTS.get(mode_name, [''])[0])}")
        return ""

    if cmd == "model":
        if not args:
            console.print(f"[bold]Current model:[/] [green]{state.get('model', 'auto')}[/]")
            console.print(f"[dim]Available: auto, {' | '.join(WORKING_ALIASES)}[/]")
            return ""
        model_name = args[0].lower()
        if model_name != "auto" and model_name not in ALL_ALIASES:
            console.print(f"[yellow]Unknown model '{model_name}'. Using 'auto'.[/]")
            model_name = "auto"
        state["model"] = model_name
        console.print(f"[green]Model set to:[/] [bold]{model_name}[/]")
        return ""

    if cmd == "models":
        from orchestrator.providers import NVIDIA_ALIASES
        table = Table(title="Available Models", box=box.ROUNDED)
        table.add_column("Alias", style="cyan")
        table.add_column("Resolved Model", style="white")
        table.add_column("Provider", style="green")
        for alias, resolved in sorted(ALL_ALIASES.items()):
            provider = "nvidia" if alias in NVIDIA_ALIASES else "ollama"
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
            console.print("[yellow]Usage: /scan <target> [--ports N-M] [--nuclei-severity <sev>][/]")
            return ""
        target = args[0]
        ports = "1-1000"
        sev = None
        for i, a in enumerate(args[1:], 1):
            if a == "--ports" and i + 1 < len(args):
                ports = args[i + 1]
            elif a == "--nuclei-severity" and i + 1 < len(args):
                sev = args[i + 1]
        result = await cmd_scan(target, ports=ports, sev=sev)
        pp(result, title=f"Scan: {target}")
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

    console.print(f"[red]Unknown command: /{cmd}[/]")
    console.print("[dim]Type /help for available commands[/]")
    return ""


RAPHAEL_DIR = Path(__file__).resolve().parent


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


async def main():
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

    _warn_weak_defaults()

    state = {"mode": "single", "model": "auto"}

    _start_services()

    console.print()
    console.print("[dim]All services should be available now. Type /help for commands.[/]")

    history = FileHistory(str(HISTORY_PATH)) if HISTORY_PATH.parent.exists() else None
    session = PromptSession(history=history)

    while True:
        try:
            prompt_text = f"raphael [{state['mode']}] > "
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
                    result = await call_llm(state["mode"], user_input)
                except Exception as e:
                    result = f"[red]Error: {e}[/]"
                    if "--debug" in sys.argv:
                        console.print(traceback.format_exc())
            print_md(result, title=f"{state['mode'].upper()} Response")


if __name__ == "__main__":
    asyncio.run(main())
