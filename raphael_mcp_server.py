#!/home/yaser/raphael-2.0/.venv/bin/python3
"""
Raphael 2.0 MCP Server — exposes Raphael tools to opencode via stdio.
"""
import asyncio
import json
import os
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP
from orchestrator.providers import call_model, WORKING_ALIASES, ALL_ALIASES
from orchestrator.proxy_guard import ProxyGuard, ProxyError

mcp = FastMCP("raphael-2.0", instructions="Raphael 2.0 Autonomous AI Security Platform MCP interface")


# ── Tool: call LLM ──────────────────────────────────────────────────────────
@mcp.tool(name="call-llm", description="Call an LLM via Raphael's provider layer")
async def call_llm(prompt: str, model: str = "auto", system_prompt: str = "") -> str:
    aliases = WORKING_ALIASES if model == "auto" else [model]
    alias = aliases[0] if aliases else "w12"
    system = [{"role": "system", "content": system_prompt}] if system_prompt else []
    result = await call_model(alias, system + [{"role": "user", "content": prompt}])
    return result or "[No response]"


@mcp.tool(name="list-models", description="List available LLM model aliases")
async def list_models() -> str:
    return json.dumps({
        "working": sorted(WORKING_ALIASES),
        "all": sorted(ALL_ALIASES.keys()),
    }, indent=2)


# ── Tool: port scan ─────────────────────────────────────────────────────────
@mcp.tool(name="nmap-scan", description="Port scan a target using nmap")
async def nmap_scan(target: str, ports: str = "1-1000", aggressive: bool = False) -> str:
    cmd = ["nmap", "-sV", "-T4"]
    if aggressive:
        cmd.append("-A")
    cmd.extend(["-p", ports, target])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "Error: nmap timed out after 300s"
    except FileNotFoundError:
        return "Error: nmap not found"


# ── Tool: nuclei scan ───────────────────────────────────────────────────────
@mcp.tool(name="nuclei-scan", description="Vulnerability scan using nuclei templates")
async def nuclei_scan(target: str, severity: str = "medium") -> str:
    cmd = ["nuclei", "-u", target, "-severity", severity, "-json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line.startswith("{"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return json.dumps({"findings": findings, "raw_output": output[:2000]}, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nuclei timed out after 300s"})
    except FileNotFoundError:
        return json.dumps({"error": "nuclei not found"})


# ── Tool: subdomain enum ────────────────────────────────────────────────────
@mcp.tool(name="subfinder", description="Enumerate subdomains using subfinder")
async def subfinder_enum(domain: str) -> str:
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        return json.dumps({"subdomains": subs}, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "subfinder timed out"})
    except FileNotFoundError:
        return json.dumps({"error": "subfinder not found"})


# ── Tool: sqlmap ────────────────────────────────────────────────────────────
@mcp.tool(name="sqlmap-scan", description="SQL injection detection using sqlmap")
async def sqlmap_scan(url: str, level: int = 3, risk: int = 2) -> str:
    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level", str(level), "--risk", str(risk)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout[-5000:] or result.stderr[-5000:]
    except subprocess.TimeoutExpired:
        return "Error: sqlmap timed out after 600s"
    except FileNotFoundError:
        return "Error: sqlmap not found"


# ── Tool: gobuster ──────────────────────────────────────────────────────────
@mcp.tool(name="gobuster", description="Directory/file enumeration with gobuster")
async def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "Error: gobuster timed out"
    except FileNotFoundError:
        return "Error: gobuster not found"


# ── Tool: torrent / proxy status ────────────────────────────────────────────
@mcp.tool(name="proxy-status", description="Check Raphael proxy (Tor) status")
async def proxy_status() -> str:
    pg = ProxyGuard()
    s = pg.status()
    ext_ip = "unknown"
    try:
        ext_ip = pg._get_exit_ip() or "unknown"
    except Exception:
        pass
    return json.dumps({
        "active": s.get("active", False),
        "strategy": s.get("strategy", "none"),
        "exit_ip": ext_ip,
        "tor_running": s.get("tor_running", False),
    }, indent=2)


# ── Tool: verify systems ────────────────────────────────────────────────────
@mcp.tool(name="verify", description="Verify all Raphael systems health")
async def verify_health() -> str:
    from raphael_cli import _verify_all
    report = await _verify_all()
    overall = all(
        v.get("pass", False) for v in report.values()
        if isinstance(v, dict)
    )
    return json.dumps({"overall": overall, "checks": report}, indent=2)


# ── Tool: model cost stats ──────────────────────────────────────────────────
@mcp.tool(name="cost-stats", description="Show Raphael API cost statistics")
async def cost_stats() -> str:
    from orchestrator.providers import cost_tracker_stats
    return json.dumps(cost_tracker_stats(), indent=2)


# ── Tool: growth db stats ───────────────────────────────────────────────────
@mcp.tool(name="knowledge-stats", description="Show Raphael knowledge base (growth) stats")
async def knowledge_stats() -> str:
    from orchestrator.growth_db import grow
    return json.dumps(grow.stats(), indent=2)


# ── Tool: payloads list ─────────────────────────────────────────────────────
@mcp.tool(name="payloads", description="Query Raphael payload database")
async def payloads_list(vector: str = "") -> str:
    from orchestrator.exploit.payloads_db import PayloadsDB
    db = PayloadsDB()
    if vector:
        return json.dumps(db.query(vector=vector), indent=2)
    return json.dumps({"available_vectors": db.vectors()}, indent=2)


# ── Tool: autonomous engagement ─────────────────────────────────────────────
@mcp.tool(name="autonomous-engage", description="Run full autonomous engagement against a target")
async def autonomous_engage(target: str, phases: str = "recon,scan,exploit") -> str:
    from orchestrator.modes import autonomous
    phase_list = [p.strip() for p in phases.split(",")]
    result = await autonomous.handle(target, phases=phase_list)
    return json.dumps(result, indent=2, default=str)


# ── Tool: web search ────────────────────────────────────────────────────────
@mcp.tool(name="web-search", description="Search the web via DuckDuckGo")
async def web_search(query: str) -> str:
    from orchestrator.web_tools import web_search as ws, format_search_results
    results = await ws(query)
    return format_search_results(results)


# ── Tool: fetch url ─────────────────────────────────────────────────────────
@mcp.tool(name="fetch-url", description="Fetch and extract text from a URL")
async def fetch_url(url: str) -> str:
    from orchestrator.web_tools import fetch_url as fu, format_fetch_result
    result = await fu(url)
    return format_fetch_result(result)


# ── Tool: debate ────────────────────────────────────────────────────────────
@mcp.tool(name="debate", description="Run multi-model debate on a question")
async def debate(question: str) -> str:
    from orchestrator.modes import debate as debate_mode
    result = await debate_mode.handle(question)
    return result.get("final", result.get("synthesis", json.dumps(result, indent=2)))


# ── Tool: deep research ─────────────────────────────────────────────────────
@mcp.tool(name="deep-research", description="Run deep research with sources on a topic")
async def deep_research(topic: str) -> str:
    from orchestrator.modes import deep_research as dr
    result = await dr.handle(topic)
    return result.get("final", result.get("rsi_output", json.dumps(result, indent=2)))


# ── Tool: tools list (from mcp-hub registry) ────────────────────────────────
@mcp.tool(name="raphael-tools", description="List all tools available in Raphael MCP Hub")
async def raphael_tools() -> str:
    hub_dir = Path(__file__).resolve().parent / "mcp-hub"
    sys.path.insert(0, str(hub_dir))
    from core.registry import ToolRegistry
    reg = ToolRegistry()
    reg.load_tools(str(hub_dir / "tools"))
    return json.dumps(reg.list_tools(), indent=2)


# ── Tool: run mcp-hub tool ──────────────────────────────────────────────────
@mcp.tool(name="run-tool", description="Run a tool from the Raphael MCP Hub by name")
async def run_hub_tool(tool_name: str, arguments: str = "{}") -> str:
    hub_dir = Path(__file__).resolve().parent / "mcp-hub"
    sys.path.insert(0, str(hub_dir))
    from core.registry import ToolRegistry
    reg = ToolRegistry()
    reg.load_tools(str(hub_dir / "tools"))
    tool = reg.get_tool(tool_name)
    if not tool:
        return json.dumps({"error": f"Tool '{tool_name}' not found. Use raphael-tools to list available."})
    params = json.loads(arguments)
    result = await tool.execute(params)
    return json.dumps(result, indent=2, default=str)


if __name__ == "__main__":
    mcp.run(transport="stdio")
