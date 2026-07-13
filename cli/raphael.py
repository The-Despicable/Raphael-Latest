#!/usr/bin/env python3
"""
Raphael 2.0 — AI Autonomous Pentesting CLI

Usage:
  raphael engage run <target> [options]
  raphael engage start <target> [options]
  raphael engage status <id>
  raphael report <id>
  raphael scan <target> [options]
  raphael chat [--model <name>]
  raphael health [--docker] [--all]
  raphael models [--list | --set <name>]
  raphael interactive
  raphael docker up|down|restart|logs|ps
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH = True
except ImportError:
    RICH = False

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
MODELS_CONFIG = SCRIPT_DIR / "models_config.json"
API_BASE = os.getenv("RAPHAEL_API", "http://localhost:3900")
API_KEY = os.getenv("RAPHAEL_API_KEY", "")


def cprint(msg="", style=None):
    if RICH and style:
        Console().print(msg, style=style)
    else:
        print(msg)


def crule(title="", style=""):
    if RICH:
        Console().rule(title, style=style)
    elif title:
        n = max(2, 54 - len(title) - 2)
        print(f"\n{'─' * (n // 2)} {title} {'─' * (n - n // 2)}\n")


def cpanel(content, title=""):
    if RICH:
        Console().print(Panel(str(content), title=title))
    else:
        print(f"\n[{title}] {content}\n")


def ctable(title, columns, rows):
    if RICH and columns and rows:
        t = Table(title=title, box=box.ROUNDED, header_style="bold cyan")
        for c in columns:
            t.add_column(c)
        for r in rows:
            t.add_row(*[str(x) for x in r])
        Console().print(t)
    else:
        if title:
            print(f"\n  {title}")
        if columns:
            widths = [max(len(str(r[i])) for r in rows + [columns]) for i in range(len(columns))]
            fmt = "    " + "  ".join(f"{{:{w}}}" for w in widths)
            print(fmt.format(*columns))
            print(f"    {'  '.join('─' * w for w in widths)}")
            for r in rows:
                print(fmt.format(*r))


def cstatus(msg):
    if RICH:
        return Console().status(msg, spinner="dots")
    class _:
        def __enter__(s): print(f"  {msg}...", end="", flush=True); return s
        def __exit__(s, *a): print(" done")
    return _()


def cconfirm(msg, default=True):
    if RICH:
        return Confirm.ask(msg, default=default)
    r = input(f"  {msg} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not r else r in ("y", "yes")


def cprompt(msg, default=None):
    if RICH:
        return Prompt.ask(msg, default=default)
    r = input(f"  {msg}: ").strip()
    return r if r else default


def load_models():
    if MODELS_CONFIG.exists():
        try:
            return json.loads(MODELS_CONFIG.read_text())
        except Exception:
            pass
    return {"default_model": "auto", "models": {}, "personas": {}, "fallback_order": []}


def get_models():
    cfg = load_models()
    return [{"alias": k, **v} for k, v in cfg.get("models", {}).items() if v.get("enabled", True)]


def get_personas():
    cfg = load_models()
    return [{"name": k, **v} for k, v in cfg.get("personas", {}).items()]


def default_model():
    return load_models().get("default_model", "auto")


def phase_override(phase):
    return load_models().get("phase_model_overrides", {}).get(phase, "") or None


async def api(method, path, body=None, timeout=300):
    import httpx
    h = {"User-Agent": "raphael-cli/2.0"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    url = f"{API_BASE}{path}"
    async with httpx.AsyncClient(timeout=timeout) as cl:
        try:
            r = await (cl.get(url, headers=h) if method == "GET" else cl.post(url, json=body or {}, headers=h))
            return r.json() if r.is_success else {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}


async def cmd_health(args):
    from cli.health_check import run_all_checks, print_results
    host = getattr(args, "host", "127.0.0.1")
    cd = getattr(args, "docker", False) or getattr(args, "all", False)
    cprint(f"\n  RAPHAEL HEALTH CHECK", "bold green")
    cprint(f"  API: {API_BASE}  |  Host: {host}  |  Docker: {'yes' if cd else 'no'}\n")
    results = await run_all_checks(host=host, check_docker=cd)
    print_results(results)


async def cmd_engage_run(args):
    model = getattr(args, "model", None) or default_model()
    body = {
        "target": args.target,
        "phases": args.phases.split(",") if args.phases else None,
        "persona": args.persona,
        "no_proxy": args.no_proxy,
        "webhook_url": args.webhook,
    }
    if model != "auto":
        body["model"] = model

    cprint(f"\n  ENGAGEMENT — {args.target}", "bold cyan")
    cprint(f"  Model: {model}  |  Phases: {args.phases or 'all'}  |  Persona: {args.persona or 'default'}")

    resp = await api("POST", "/v1/ci/engage", body)
    eid = resp.get("id", "")
    if not eid or "error" in resp:
        cprint(f"  Failed: {resp.get('error', 'Failed')}", "bold red")
        sys.exit(1)

    cprint(f"  Engagement {eid} queued", "bold green")

    if RICH:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=False) as p:
            t = p.add_task("Waiting...", total=None)
            while True:
                await asyncio.sleep(3)
                s = await api("GET", f"/v1/ci/engage/{eid}")
                st = s.get("status", "")
                ph = s.get("current_phase", "")
                fcnt = s.get("findings_count", 0)
                p.update(t, description=f"Phase: {ph or 'waiting':12}  Status: {st:8}  Findings: {fcnt}")
                if st in ("complete", "failed"):
                    break
    else:
        while True:
            await asyncio.sleep(5)
            s = await api("GET", f"/v1/ci/engage/{eid}")
            st = s.get("status", "")
            ph = s.get("current_phase", "")
            fcnt = s.get("findings_count", 0)
            print(f"  {st:8} | {ph or 'waiting':12} | {fcnt} findings", end="\r")
            if st in ("complete", "failed"):
                print()
                break

    if s.get("status") == "failed":
        cprint(f"  Failed: {s.get('error', '?')}", "bold red")
        sys.exit(1)

    report = await api("GET", f"/v1/ci/report/{eid}")
    show_report(report, args.target)


async def cmd_engage_start(args):
    model = getattr(args, "model", None) or default_model()
    body = {
        "target": args.target,
        "phases": args.phases.split(",") if args.phases else None,
        "persona": args.persona,
        "no_proxy": args.no_proxy,
        "webhook_url": args.webhook,
    }
    if model != "auto":
        body["model"] = model

    resp = await api("POST", "/v1/ci/engage", body)
    eid = resp.get("id", "")
    if eid:
        cprint(f"  {eid}", "bold green")
        print(eid)
    else:
        cprint(f"  {resp.get('error', 'Failed')}", "bold red")
        sys.exit(1)


async def cmd_engage_status(args):
    d = await api("GET", f"/v1/ci/engage/{args.id}")
    if "error" in d:
        cprint(f"  {d['error']}", "bold red")
        sys.exit(1)
    rows = [
        ["Target", d.get("target", "?")],
        ["Status", d.get("status", "?")],
        ["Phase", d.get("current_phase", "N/A")],
        ["Completed", str(d.get("phases_completed", []))],
        ["Findings", str(d.get("findings_count", 0))],
        ["Created", str(d.get("created_at", "?"))[:19]],
        ["Updated", str(d.get("updated_at", "?"))[:19]],
    ]
    if d.get("error"):
        rows.append(["Error", d["error"]])
    ctable("ENGAGEMENT STATUS", ["Property", "Value"], rows)


async def cmd_report(args):
    fmt = getattr(args, "format", "json")
    d = await api("GET", f"/v1/ci/report/{args.id}?format={fmt}")
    if "error" in d:
        cprint(f"  {d['error']}", "bold red")
        sys.exit(1)
    if getattr(args, "raw", False) or fmt != "json":
        print(json.dumps(d, indent=2, default=str))
    else:
        show_report(d, d.get("target", "?"))


async def cmd_scan(args):
    model = getattr(args, "model", None) or default_model()
    body = {"target": args.target, "persona": args.persona, "no_proxy": args.no_proxy}
    if model != "auto":
        body["model"] = model

    cprint(f"\n  QUICK SCAN — {args.target}  (model: {model})", "bold yellow")
    with cstatus("Scanning..."):
        d = await api("POST", "/v1/ci/scan", body)
    if "error" in d:
        cprint(f"  {d['error']}", "bold red")
        sys.exit(1)

    total = d.get("total_findings", 0)
    cprint(f"  Complete — {total} findings\n", "bold green")
    for pn, pd in d.get("phases", {}).items():
        if isinstance(pd, dict):
            ok = pd.get("success", False)
            fs = pd.get("findings", [])
            cprint(f"  {'OK' if ok else 'FAIL'} {pn.upper()}: {len(fs)} findings")
            for f in fs[:5]:
                desc = f.get("description", f.get("type", "?"))[:120]
                sev = f.get("severity", "info")
                cprint(f"      [{sev}] {desc}")
            if len(fs) > 5:
                cprint(f"      ... +{len(fs) - 5} more")


async def cmd_chat(args):
    model = getattr(args, "model", None) or "auto"
    cprint(f"\n  RAPHAEL CHAT  (model: {model})", "bold magenta")
    cprint("  Type 'exit' or 'quit' to end.\n")
    msgs = []
    while True:
        try:
            u = input(f"  [{model}] You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not u:
            continue
        if u.lower() in ("exit", "quit"):
            break
        msgs.append({"role": "user", "content": u})
        with cstatus("Thinking..."):
            r = await api("POST", "/agent/chat", {
                "model": model, "messages": msgs, "max_tokens": 4096, "temperature": 0.85,
            })
        resp = r.get("response", r.get("error", "—"))
        if "error" in r:
            cprint(f"  {resp}", "bold red")
        else:
            print(f"\n  {resp}\n")
            msgs.append({"role": "assistant", "content": resp})


async def cmd_models(args):
    if getattr(args, "set_model", None):
        cfg = load_models()
        m = args.set_model
        avail = [x["alias"] for x in get_models()]
        if m not in avail and m != "auto":
            cprint(f"  Unknown model: {m}. Available: {', '.join(avail)}", "bold red")
            sys.exit(1)
        cfg["default_model"] = m
        MODELS_CONFIG.write_text(json.dumps(cfg, indent=2))
        cprint(f"  Default model set to '{m}'", "bold green")
        return

    cprint("\n  AVAILABLE MODELS", "bold cyan")
    models = get_models()
    dflt = default_model()
    rows = []
    for m in models:
        d = "*" if m["alias"] == dflt else " "
        tools = "Y" if m.get("supports_tools") else "N"
        caps = ", ".join(m.get("capabilities", [])[:3])
        rows.append([d, m["alias"], m.get("display", m["alias"]), m.get("provider", "?"), tools, caps])
    ctable("", ["", "Alias", "Name", "Provider", "Tools", "Capabilities"], rows)

    px = get_personas()
    if px:
        cprint("\n  Personas:", "bold")
        for p in px:
            cprint(f"    {p.get('name', '?'):15}  {p.get('display', '?')}")

    cprint(f"\n  Set default: raphael models --set <alias>")
    cprint(f"  Use: raphael scan <target> --model <alias>\n")


async def cmd_interactive(args):
    cprint("\n  RAPHAEL INTERACTIVE", "bold green")
    cprint("  Type 'help' for commands, 'exit' to quit.\n")

    st = {"target": None, "model": default_model(), "persona": "default", "phases": "recon,scan,exploit,postex", "last": None}

    while True:
        try:
            cmd = input(f"  [{st['target'] or 'none'}] raphael> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        p = cmd.split()
        a = p[0].lower()

        if a in ("exit", "quit"):
            break
        elif a == "help":
            for c, d in [
                ("target <x>", "Set target"), ("model <x>", "Set model"),
                ("persona <x>", "Set persona"), ("phases <x>", "Set phases"),
                ("run", "Run engagement"), ("scan", "Quick scan"),
                ("status", "Check last"), ("health", "Health checks"),
                ("models", "List models"), ("state", "Show state"), ("exit", "Quit"),
            ]:
                print(f"    {c:25}  {d}")
        elif a == "state":
            for k, v in st.items():
                print(f"    {k.replace('_', ' ').title():20}  {v}")
        elif a == "target" and len(p) > 1:
            st["target"] = p[1]
            cprint(f"  Target: {p[1]}", "green")
        elif a == "model" and len(p) > 1:
            avail = [x["alias"] for x in get_models()]
            if p[1] in avail or p[1] == "auto":
                st["model"] = p[1]
                cprint(f"  Model: {p[1]}", "green")
            else:
                cprint(f"  Unknown. Try: {', '.join(avail)}", "bold red")
        elif a == "persona" and len(p) > 1:
            st["persona"] = p[1]
            cprint(f"  Persona: {p[1]}", "green")
        elif a == "phases" and len(p) > 1:
            st["phases"] = p[1]
            cprint(f"  Phases: {p[1]}", "green")
        elif a == "run":
            if not st["target"]:
                cprint("  Set a target first", "bold red")
                continue
            ma = lambda: None
            for k in ["target", "phases", "persona", "model"]:
                setattr(ma, k, st[k])
            ma.no_proxy = False
            ma.webhook = None
            ma.raw = False
            ma.format = "json"
            await cmd_engage_run(ma)
        elif a == "scan":
            if not st["target"]:
                cprint("  Set a target first", "bold red")
                continue
            ma = lambda: None
            for k in ["target", "persona", "model"]:
                setattr(ma, k, st[k])
            ma.no_proxy = False
            ma.raw = False
            await cmd_scan(ma)
        elif a == "status":
            if st["last"]:
                ma = lambda: None
                ma.id = st["last"]
                ma.raw = False
                await cmd_engage_status(ma)
            else:
                cprint("  No previous engagement", "yellow")
        elif a == "health":
            ma = lambda: None
            ma.host = "127.0.0.1"
            ma.docker = False
            ma.all = False
            await cmd_health(ma)
        elif a == "models":
            ma = lambda: None
            ma.set_model = None
            await cmd_models(ma)
        else:
            cprint(f"  Unknown: {a}. Type 'help'", "yellow")


async def cmd_docker(args):
    action = getattr(args, "action", "ps")
    svc = getattr(args, "service", None)
    cf = PROJECT_ROOT / "docker-compose.yml"
    if not cf.exists():
        cprint(f"  docker-compose.yml not found at {cf}", "bold red")
        sys.exit(1)

    cprint(f"\n  DOCKER {action.upper()}", "bold cyan")
    cmd = ["docker", "compose", "-f", str(cf)]

    if action == "up":
        cmd.extend(["up", "-d"])
        if svc:
            cmd.append(svc)
    elif action == "down":
        cmd.append("down")
    elif action == "restart":
        cmd.append("restart")
        if svc:
            cmd.append(svc)
    elif action == "logs":
        cmd.extend(["logs", "--tail", "50"])
        if svc:
            cmd.append(svc)
    elif action == "ps":
        cmd.append("ps")

    try:
        subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    except FileNotFoundError:
        cprint("  Docker not found", "bold red")
        sys.exit(1)


def show_report(data, target):
    total = data.get("total_findings", 0)
    phases = data.get("phases", {})
    flags = data.get("flags", {})

    cprint(f"\n  REPORT — {target}", "bold green")
    cprint(f"  Total findings: {total}")
    if flags:
        cprint(f"  Flags: {'ALL' if flags.get('all_flags_captured') else 'PARTIAL'}", "bold yellow")
        if flags.get("user_flag"):
            cprint(f"    User:  {flags['user_flag'][:80]}")
        if flags.get("root_flag"):
            cprint(f"    Root:  {flags['root_flag'][:80]}")
    print()

    for pn, pd in phases.items():
        if not isinstance(pd, dict):
            continue
        ok = pd.get("success", False)
        fs = pd.get("findings", [])
        lat = pd.get("latency", 0)
        err = pd.get("error")
        summ = pd.get("summary", {})
        strat = pd.get("strategist", "")

        cprint(f"  {'OK' if ok else 'FAIL'} {pn.upper()}  ({lat:.1f}s)",
               "green" if ok else "red" if err else "")

        if err:
            cprint(f"    Error: {err}", "red")
        if isinstance(summ, dict):
            for k, v in summ.items():
                cprint(f"    {k}: {v}")

        if fs:
            groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for f in fs:
                groups.get(f.get("severity", "info").lower(), groups["info"]).append(f)
            for sev, items in groups.items():
                if not items:
                    continue
                cprint(f"    [{sev.upper()}] {len(items)}")
                for f in items[:3]:
                    cprint(f"      - {f.get('description', f.get('type', '?'))[:120]}")
                if len(items) > 3:
                    cprint(f"      ... +{len(items) - 3}")

        if strat:
            cprint(f"    Strategist: {strat[:200]}")
        print()


def build_parser():
    p = argparse.ArgumentParser(
        prog="raphael",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Raphael 2.0 — AI Autonomous Penetration Testing",
        epilog=textwrap.dedent("""\
            Examples:
              raphael scan 192.168.1.1
              raphael engage run 10.0.0.5 --phases recon,scan,exploit
              raphael engage run target.com --model w13 --persona redteam
              raphael models --list
              raphael health --all
              raphael interactive
              raphael docker ps
              raphael chat --model auto
        """),
    )
    p.add_argument("--raw", action="store_true", help="Raw JSON output")
    p.add_argument("--model", default=None, help=f"Model (default: {default_model()})")
    p.add_argument("--version", action="version", version="Raphael 2.0.0")
    s = p.add_subparsers(dest="command")

    h = s.add_parser("health", help="Check services and dependencies")
    h.add_argument("--host", default="127.0.0.1")
    h.add_argument("--docker", action="store_true")
    h.add_argument("--all", action="store_true")
    h.set_defaults(func=cmd_health)

    eg = s.add_parser("engage", help="Manage engagements")
    es = eg.add_subparsers(dest="action")
    for name, desc, fn in [
        ("run", "Blocking with progress", cmd_engage_run),
        ("start", "Non-blocking, returns ID", cmd_engage_start),
    ]:
        e = es.add_parser(name, help=desc)
        e.add_argument("target")
        e.add_argument("--phases")
        e.add_argument("--persona")
        e.add_argument("--no-proxy", action="store_true")
        e.add_argument("--webhook")
        e.set_defaults(func=fn)

    st = es.add_parser("status", help="Check engagement status")
    st.add_argument("id")
    st.set_defaults(func=cmd_engage_status)

    r = s.add_parser("report", help="Get report")
    r.add_argument("id")
    r.add_argument("--format", default="json", choices=["json", "sarif", "junit"])
    r.set_defaults(func=cmd_report)

    sc = s.add_parser("scan", help="Quick scan")
    sc.add_argument("target")
    sc.add_argument("--persona")
    sc.add_argument("--no-proxy", action="store_true")
    sc.set_defaults(func=cmd_scan)

    ch = s.add_parser("chat", help="Interactive chat")
    ch.set_defaults(func=cmd_chat)

    m = s.add_parser("models", help="List/set models")
    m.add_argument("--list", action="store_true")
    m.add_argument("--set", dest="set_model", metavar="ALIAS")
    m.set_defaults(func=cmd_models)

    s.add_parser("interactive", help="Full interactive mode").set_defaults(func=cmd_interactive)

    d = s.add_parser("docker", help="Manage Docker services")
    d.add_argument("action", choices=["up", "down", "restart", "logs", "ps"])
    d.add_argument("service", nargs="?")
    d.set_defaults(func=cmd_docker)

    return p


def main():
    banner = """
    +--------------------------------------------+
    |  Raphael 2.0 — Autonomous Security         |
    |  AI-Powered Penetration Testing            |
    +--------------------------------------------+"""
    if RICH:
        Console().print(Panel(banner.strip(), style="bold red"))
    else:
        print(banner)

    p = build_parser()
    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
        sys.exit(1)

    if args.command in ("engage", "report", "scan", "chat") and args.command != "health":
        import socket
        try:
            h, pr = API_BASE.replace("http://", "").split(":")
            s = socket.socket()
            s.settimeout(2)
            s.connect((h, int(pr)))
            s.close()
        except Exception:
            cprint(f"  Cannot reach API at {API_BASE}", "yellow")
            if not cconfirm("Continue anyway?", False):
                sys.exit(1)

    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
