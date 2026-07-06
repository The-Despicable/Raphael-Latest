#!/usr/bin/env python3
"""
OpenCode MCP Server — Telegram Bridge
Gives OpenCode tools to: notify you on Telegram, run shell commands,
read/write files, check git status. Runs as an MCP stdio server.
"""

import os, subprocess, asyncio, re, shlex
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("opencode-telegram")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
CHAT_ID        = os.getenv("TELEGRAM_CHAT_ID", "")
DEFAULT_DIR    = os.getenv("WORK_DIR", os.path.expanduser("~"))


# ─── Internal helpers ──────────────────────────────────────────────────────────

_tg_transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")

async def _tg(text: str, parse_mode: str = "Markdown"):
    """Fire-and-forget Telegram message."""
    if not TELEGRAM_TOKEN or not CHAT_ID:
        return
    try:
        async with httpx.AsyncClient(timeout=10, transport=_tg_transport) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": CHAT_ID, "text": text, "parse_mode": parse_mode}
            )
    except Exception:
        pass


_SAFE_ARG_RE = re.compile(r'^[a-zA-Z0-9_.\-@:/]+$')

def _validate_shell_arg(arg: str) -> str:
    if not _SAFE_ARG_RE.match(arg):
        raise ValueError(f"Unsafe argument: {arg[:50]!r}")
    return arg


def _run(cmd, cwd: str = DEFAULT_DIR, timeout: int = 120) -> dict:
    try:
        if isinstance(cmd, str):
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        else:
            r = subprocess.run(list(cmd), shell=False, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        return {
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
            "returncode": r.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": -1}
    except ValueError:
        raise
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


# ─── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
async def notify_telegram(message: str) -> str:
    """
    Send a progress update or result to the user's Telegram.
    Use this to keep the user informed about what you're doing,
    especially before and after long operations.
    """
    await _tg(f"🤖 *OpenCode:*\n{message}")
    return "Notification sent to Telegram."


@mcp.tool()
async def run_shell(command: str, working_dir: str = "") -> str:
    """
    Execute a shell command and return stdout + stderr.
    Also sends a Telegram notification with the result for visibility.
    working_dir defaults to WORK_DIR env var.
    """
    cwd = working_dir or DEFAULT_DIR
    await _tg(f"▶️ Running:\n`{command}`")
    result = _run(command, cwd=cwd)

    output = result["stdout"] or result["stderr"] or "(no output)"
    icon = "✅" if result["returncode"] == 0 else "❌"
    await _tg(f"{icon} Exit {result['returncode']}:\n```\n{output[:1500]}\n```")
    return output


@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file and return its contents."""
    try:
        full = os.path.expanduser(path)
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"Error reading {path}: {e}"


@mcp.tool()
async def write_file(path: str, content: str) -> str:
    """
    Write content to a file (creates parent dirs if needed).
    Notifies Telegram when done.
    """
    try:
        full = os.path.expanduser(path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        await _tg(f"✅ File written: `{path}`")
        return f"Written {len(content)} chars to {path}"
    except Exception as e:
        return f"Error writing {path}: {e}"


@mcp.tool()
async def list_directory(path: str = ".") -> str:
    """List directory contents with file sizes."""
    safe_path = _validate_shell_arg(path.lstrip("/"))
    result = _run(["ls", "-lah", safe_path])
    return result["stdout"] or result["stderr"]


@mcp.tool()
async def git_status(repo_path: str = ".") -> str:
    """
    Get git status + recent commits for a repo.
    Useful for checking what changed after edits.
    """
    cwd = repo_path or DEFAULT_DIR
    out = ""
    for cmd in [["git", "status", "--short"], ["git", "log", "--oneline", "-8"], ["git", "diff", "--stat"]]:
        r = _run(cmd, cwd=cwd)
        if r["stdout"]:
            out += f"$ {' '.join(cmd)}\n{r['stdout']}\n\n"
    return out.strip() or "No git info found."


@mcp.tool()
async def search_in_files(pattern: str, path: str = ".", file_ext: str = "") -> str:
    """
    Search for a pattern across files (grep).
    pattern: regex or text to search for
    file_ext: optional filter like '.py' or '.ts'
    """
    safe_pattern = _validate_shell_arg(pattern)
    cmd = ["grep", "-rn"]
    if file_ext:
        safe_ext = _validate_shell_arg(file_ext)
        cmd.extend([f"--include=*.{safe_ext}"])
    cmd.extend(["--", safe_pattern, path])
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=30, cwd=DEFAULT_DIR)
        return r.stdout.strip() or "No matches found."
    except subprocess.TimeoutExpired:
        return "Timed out during search."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
async def get_system_status() -> str:
    """Get CPU, RAM, disk usage — useful to check before heavy operations."""
    cmds = {
        "CPU/Load": ["uptime"],
        "Memory": ["free", "-h"],
        "Disk": ["df", "-h", "/"],
        "Running processes": ["ps", "aux", "--sort=-%cpu"],
    }
    out = ""
    for label, cmd in cmds.items():
        r = _run(cmd)
        out += f"### {label}\n{r['stdout']}\n\n"
    return out.strip()


@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file and return its contents."""
    try:
        full = os.path.expanduser(path)
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"Error reading {path}: {e}"


@mcp.tool()
async def write_file(path: str, content: str) -> str:
    """
    Write content to a file (creates parent dirs if needed).
    Notifies Telegram when done.
    """
    try:
        full = os.path.expanduser(path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        await _tg(f"✅ File written: `{path}`")
        return f"Written {len(content)} chars to {path}"
    except Exception as e:
        return f"Error writing {path}: {e}"


@mcp.tool()
async def list_directory(path: str = ".") -> str:
    """List directory contents with file sizes."""
    result = _run(f"ls -lah {path}")
    return result["stdout"] or result["stderr"]


@mcp.tool()
async def git_status(repo_path: str = ".") -> str:
    """
    Get git status + recent commits for a repo.
    Useful for checking what changed after edits.
    """
    cwd = repo_path or DEFAULT_DIR
    out = ""
    for cmd in ["git status --short", "git log --oneline -8", "git diff --stat"]:
        r = _run(cmd, cwd=cwd)
        if r["stdout"]:
            out += f"$ {cmd}\n{r['stdout']}\n\n"
    return out.strip() or "No git info found."


@mcp.tool()
async def search_in_files(pattern: str, path: str = ".", file_ext: str = "") -> str:
    """
    Search for a pattern across files (grep).
    pattern: regex or text to search for
    file_ext: optional filter like '.py' or '.ts'
    """
    ext_flag = f"--include='*{file_ext}'" if file_ext else ""
    cmd = f"grep -rn {ext_flag} '{pattern}' {path} 2>/dev/null | head -50"
    result = _run(cmd)
    return result["stdout"] or "No matches found."


@mcp.tool()
async def get_system_status() -> str:
    """Get CPU, RAM, disk usage — useful to check before heavy operations."""
    cmds = {
        "CPU/Load": "uptime",
        "Memory": "free -h",
        "Disk": "df -h /",
        "Running processes": "ps aux --sort=-%cpu | head -8"
    }
    out = ""
    for label, cmd in cmds.items():
        r = _run(cmd)
        out += f"### {label}\n{r['stdout']}\n\n"
    return out.strip()


if __name__ == "__main__":
    mcp.run()
