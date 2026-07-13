#!/usr/bin/env python3
import asyncio
import json
import logging
import shlex
import subprocess
from aiohttp import web
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kali-tools")

async def run_tool(request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    
    tool = data.get("tool", "")
    args = data.get("args", "")
    timeout = data.get("timeout", 300)
    
    if not tool:
        return web.json_response({"error": "tool required"}, status=400)
    
    cmd_str = f"{tool} {args}"
    try:
        cmd_list = shlex.split(f"{tool} {args}")
    except Exception as e:
        return web.json_response({"error": f"shlex split failed: {e}", "tool": tool, "stdout": "", "stderr": ""})
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return web.json_response({"error": f"Timeout after 300s", "tool": tool, "stdout": "", "stderr": "timeout"})
        
        return web.json_response({
            "tool": tool,
            "returncode": 0,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        })
    except FileNotFoundError:
        return web.json_response({"error": f"Tool not found: {tool}", "tool": tool, "stdout": "", "stderr": ""})
    except Exception as e:
        return web.json_response({"error": str(e), "tool": tool, "stdout": "", "stderr": ""})

async def health(request):
    return web.json_response({"status": "healthy"})

async def list_tools(request):
    return web.json_response({"tools": ["nmap", "nuclei", "gobuster", "sqlmap", "hashcat", "crackmapexec"]})

app = web.Application()
app.router.add_get('/health', health)
app.router.add_get('/tools', list_tools)
app.router.add_post('/run', run_tool)

if __name__ == '__main__':
    import aiohttp.web
    aiohttp.web.run_app(app, host='0.0.0.0', port=3800)