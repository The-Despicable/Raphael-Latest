#!/home/yaser/raphael-2.0/.venv/bin/python3
"""
Raphael Brain — Executive reasoning loop.

Architecture:
  Executive model reasons → brain extracts intent from natural language → dispatches tool
  Model output is parsed for action keywords, no strict JSON required.

Usage:
  python raphael_brain.py "Own 10.129.54.70 and capture both flags"
  python raphael_brain.py --resume <session_id>
"""

import asyncio
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator.providers import call_model

EXEC_MODEL = "oc-nemotron-ultra-free"
MAX_ITERATIONS = 30
SESSION_DIR = Path("/tmp/raphael_brain_sessions")
SESSION_DIR.mkdir(parents=True, exist_ok=True)

TOOL_DESCRIPTIONS = {
    "nmap-scan": "Port scan a target. target(str) required, ports(str)='1-1000', aggressive(bool)=false",
    "gobuster": "Directory/file enumeration. url(str) required, mode(str)='dir', wordlist(str)='/usr/share/wordlists/dirb/common.txt'",
    "sqlmap-scan": "SQL injection detection. url(str) required, level(int)=3, risk(int)=2",
    "craftcms-exploit": "CVE-2025-32432 CraftCMS RCE. REQUIRED: host(str) on EVERY call. cmd(str)='id'. Each call is a FRESH exploit chain — no session persistence.",
    "call-model": "Call any model. model(str) required, prompt(str) required, system_prompt(str)=''",
    "fetch-url": "Fetch URL content. url(str) required",
    "web-search": "Search the web. query(str) required",
    "harvest": "Run FULL harvest cycle: ingest CVEs from NVD/Exploit-DB/CISA KEV, scrape GitHub for PoC repos, poll security news feeds, extract techniques from all sources, integrate into GrowthDB. No params required.",
    "harvest-search": "Search harvested techniques and CVEs. query(str) required, source(str)='all' (cve/technique/all)",
    "done": "Objective complete. summary(str) optional, user_flag(str)='', root_flag(str)=''",
}


async def run_tool(name: str, params: dict) -> str:
    import subprocess
    try:
        if name == "nmap-scan":
            cmd = ["nmap", "-sV", "-T4", "-Pn"]
            if params.get("aggressive"):
                cmd.append("-A")
            cmd.extend(["-p", params.get("ports", "1-1000"), params.get("target", params.get("host", ""))])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return (r.stdout or r.stderr)[:2000]

        elif name == "gobuster":
            cmd = ["gobuster", params.get("mode", "dir"), "-u", params.get("url", ""),
                   "-w", params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return (r.stdout or r.stderr)[:2000]

        elif name == "sqlmap-scan":
            cmd = ["sqlmap", "-u", params.get("url", ""), f"--level={params.get('level', 3)}",
                   f"--risk={params.get('risk', 2)}", "--batch", "--random-agent"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return (r.stdout or r.stderr)[:2000]

        elif name == "craftcms-exploit":
            import subprocess, os
            exploit_script = os.path.join(os.path.dirname(__file__), "exploit_session.py")
            host = params.get("host", "")
            port = params.get("port", 80)
            cmd = params.get("cmd", "id")
            if not host:
                return "Error: host parameter required"
            # Run the exploit script with the target
            result = subprocess.run(
                [sys.executable, exploit_script, host, str(port), cmd],
                capture_output=True, text=True, timeout=120
            )
            return (result.stdout or result.stderr)[:3000]

        elif name == "call-model":
            model = params.get("model", "gemma4")
            prompt = params.get("prompt", "")
            system_prompt = params.get("system_prompt", "")
            system = [{"role": "system", "content": system_prompt}] if system_prompt else []
            result = await call_model(model, system + [{"role": "user", "content": prompt}])
            return (result or "[No response]")[:2000]

        elif name == "fetch-url":
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.get(params.get("url", ""), timeout=30, follow_redirects=True)
                return r.text[:3000]

        elif name == "web-search":
            import httpx
            q = params.get("query", "")
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"https://lite.duckduckgo.com/lite/?q={q}",
                    headers={"User-Agent": "Mozilla/5.0"}, timeout=30
                )
                return r.text[:3000]

        elif name == "harvest":
            from orchestrator.harvester.harvester_engine import get_harvester
            engine = get_harvester()
            cycle = await engine.run_full_cycle(target=params.get("target", ""))
            return (
                f"Cycle {cycle.cycle_id}: {cycle.techniques_extracted} techniques extracted, "
                f"{cycle.techniques_integrated} integrated in {cycle.completed - cycle.started:.1f}s"
            )

        elif name == "harvest-search":
            from orchestrator.harvester.harvester_engine import get_harvester
            engine = get_harvester()
            query = params.get("query", "")
            source = params.get("source", "all")
            results = engine.search(query, source)
            return json.dumps(results[:10], indent=2)[:2000]

        elif name == "done":
            return f'__DONE__:{json.dumps(params)}'

        else:
            return f"Error: unknown tool '{name}'"

    except subprocess.TimeoutExpired:
        return f"Error: tool '{name}' timed out"
    except FileNotFoundError as e:
        return f"Error: {e} — tool binary not found"
    except Exception as e:
        return f"Error: {name} failed: {e}"


def parse_intent(text: str) -> dict:
    """Parse natural language model output into action/tool/params."""
    text = text.strip()

    # Try JSON first
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            d = json.loads(m.group(0))
            action = d.get("action", d.get("type", "tool"))
            tool = d.get("tool", d.get("command", ""))
            params = d.get("params", d.get("args", d.get("parameters", {})))
            if action in ("tool", "model", "done") and tool and isinstance(params, dict):
                return {"action": action, "tool": tool, "params": params, "reasoning": d.get("reasoning", text[:100])}
        except (json.JSONDecodeError, AttributeError):
            pass

    text_lower = text.lower()
    action = "tool"
    tool = ""
    params = {}

    # Done detection - only match explicit completion with flags or "Done." at end
    if re.search(r'(?:user|usr)[_.]?(?:flag|txt)[=:\s]*[a-f0-9]{32}', text, re.IGNORECASE) or \
       re.search(r'root[_.]?(?:flag|txt)[=:\s]*[a-f0-9]{32}', text, re.IGNORECASE) or \
       (re.search(r'^\s*done\s*[.:]', text_lower) or re.search(r'\bdone\s*[.:]\s*$', text_lower)):
        user_m = re.search(r'(?:user|usr)[_.]?(?:flag|txt)[=:\s]*([a-f0-9]{32})', text, re.IGNORECASE)
        root_m = re.search(r'root[_.]?(?:flag|txt)[=:\s]*([a-f0-9]{32})', text, re.IGNORECASE)
        action = "done"
        if user_m: params["user_flag"] = user_m.group(1)
        if root_m: params["root_flag"] = root_m.group(1)
        return {"action": action, "tool": tool, "params": params, "reasoning": text[:100]}

    # Tool detection order matters (check more specific before less)
    if re.search(r'\bharvest\b.*\bsearch\b|\bsearch\b.*\bharvest\b', text_lower):
        tool = "harvest-search"
        m = re.search(r'(?:query|for|about)\s+["\']?([^"\'\n,.]+)["\']?', text)
        if m: params["query"] = m.group(1)
    elif re.search(r'\bharvest\b', text_lower):
        tool = "harvest"
    elif re.search(r'\bcall\b.*\bmodel\b|\bcall\b.*\bgemma4\b|\bcall\b.*\bkimi\b', text_lower):
        tool = "call-model"
        m = re.search(r'\b(gemma4|kimi|oc-deepseek|oc-nemotron|oc-deepseek-free|oc-hy3-free|oc-big-pickle|oc-mimo-free|oc-nemotron-ultra-free|oc-north-mini-code-free)\b', text_lower)
        if m: params["model"] = m.group(1)
        m = re.search(r'(?:prompt|about|analyze)[=:\s]+["\']?([^"\'\n,.]+)["\']?', text)
        if m: params["prompt"] = m.group(1)
    elif re.search(r'\bnmap\b', text_lower):
        tool = "nmap-scan"
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
        if m: params["target"] = m.group(0)
        m = re.search(r'(?:ports?| -p)\s*(\S+)', text)
        if m: params["ports"] = m.group(1).rstrip(',')
        if re.search(r'-A|aggressive', text_lower): params["aggressive"] = True
    elif re.search(r'\bgobuster\b', text_lower):
        tool = "gobuster"
        m = re.search(r'(https?://[^\s,]+)', text)
        if m: params["url"] = m.group(0)
    elif re.search(r'\bsqlmap\b', text_lower):
        tool = "sqlmap-scan"
        m = re.search(r'(https?://[^\s,]+)', text)
        if m: params["url"] = m.group(0)
    elif re.search(r'\bcraftcms\b|\bcve-?2025-?32432\b', text_lower):
        tool = "craftcms-exploit"
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
        if m: params["host"] = m.group(0)
        m = re.search(r'(?:cmd|command)\s*[=:]\s*["\']?([^"\'\n,.]+)["\']?', text)
        if m: params["cmd"] = m.group(1)
    elif re.search(r'\bsearch|google|duckduckgo\b', text_lower):
        tool = "web-search"
        m = re.search(r'(?:search|for|about)\s+["\']?([^"\'\n,.]+)["\']?', text)
        if m: params["query"] = m.group(1)
    elif re.search(r'\bfetch|curl|get|http', text_lower):
        tool = "fetch-url"
        m = re.search(r'(https?://[^\s,]+)', text)
        if m: params["url"] = m.group(0)

    if not tool:
        m = re.search(r'(https?://[^\s,]+)', text)
        if m:
            tool = "fetch-url"
            params["url"] = m.group(0)
        else:
            m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
            if m:
                tool = "nmap-scan"
                params["target"] = m.group(0)

    return {"action": action, "tool": tool, "params": params, "reasoning": text[:100]}


def save_session(session_id: str, history: list, objective: str):
    path = SESSION_DIR / f"{session_id}.json"
    data = {"session_id": session_id, "objective": objective, "history": history,
            "updated": datetime.now().isoformat()}
    path.write_text(json.dumps(data, indent=2))


def load_session(session_id: str) -> dict | None:
    path = SESSION_DIR / f"{session_id}.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


async def run(objective: str, session_id: str | None = None, resume=False):
    session_id = session_id or str(uuid.uuid4())[:8]
    history = []
    if resume:
        session = load_session(session_id)
        if session:
            history = session["history"]
            objective = session.get("objective", objective)

    print(f"\n{'='*60}")
    print(f"  RAPHAEL BRAIN")
    print(f"  Session: {session_id}")
    print(f"  Executive: {EXEC_MODEL}")
    print(f"  Objective: {objective}")
    print(f"{'='*60}\n")

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n── Iteration {iteration} ──")

        ctx = ""
        if history:
            last = history[-1]
            ctx = f"Previous result: {last.get('output', '')[:300]}"

        tools_short = ", ".join(TOOL_DESCRIPTIONS.keys())
        user_msg = f"""Objective: {objective}

Current state: {len(history)} steps done.
{ctx}

Available: {tools_short}

What should I do next? Just explain in natural language. I'll figure out the tool and params from your explanation."""

        prompt = f"""You are the executive brain of Raphael security platform. Output ONE short command for the next immediate step.

Current objective: {objective}
Context: {ctx}

Examples:
"Run nmap scan on 10.129.54.86 ports 80,443"
"Fetch http://10.129.54.86/ with curl"
"Search the web for CraftCMS exploit"
"Call gemma4 to analyze the results"
"Done. user.txt=8e6138303609780c522e87444afe2d4b, root.txt=cae28ccecf9899c53c68c3488285791b"

ONLY output the next single step. No plans, no sections, no markdown."""

        print("  Thinking...")
        raw = await call_model(EXEC_MODEL, [
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_msg}
        ])
        if not raw:
            print("  Empty response, retrying")
            continue

        print(f"  Raw: {raw[:200]}")
        intent = parse_intent(raw)
        action = intent["action"]
        tool = intent["tool"]
        params = intent["params"]
        print(f"  Parsed: {action} / {tool} / {params}")

        if action == "done":
            print(f"\n  DONE: {params.get('summary', 'Objective complete')}")
            if params.get("user_flag"): print(f"     user.txt: {params['user_flag']}")
            if params.get("root_flag"): print(f"     root.txt: {params['root_flag']}")
            history.append({
                "raw_output": raw, "intent": intent,
                "action": action, "tool": tool, "params": params,
                "output": f"DONE: {params.get('summary', '')}",
            })
            save_session(session_id, history, objective)
            return {"session_id": session_id, "status": "complete",
                    "user_flag": params.get("user_flag", ""),
                    "root_flag": params.get("root_flag", ""),
                    "iterations": iteration}

        print(f"  → Running {tool}...")
        result = await run_tool(tool, params)
        print(f"  └─ {result[:200]}")

        history.append({
            "raw_output": raw, "intent": intent,
            "action": action, "tool": tool, "params": params,
            "output": result[:2000],
        })
        save_session(session_id, history, objective)

    print(f"\n  Max iterations ({MAX_ITERATIONS}) reached.")
    return {"session_id": session_id, "status": "max_iterations", "iterations": MAX_ITERATIONS}


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Raphael Brain")
    parser.add_argument("objective", nargs="?", help="Engagement objective")
    parser.add_argument("--resume", help="Resume session by ID")
    parser.add_argument("--list", action="store_true", help="List sessions")
    args = parser.parse_args()

    if args.list:
        for p in sorted(SESSION_DIR.glob("*.json")):
            data = json.loads(p.read_text())
            print(f"  {p.stem}: {data.get('objective', '?')[:60]} ({len(data['history'])} steps)")
        return

    if args.resume:
        result = await run("", session_id=args.resume, resume=True)
    elif args.objective:
        result = await run(args.objective)
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
