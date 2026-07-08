import httpx, json, os, shlex
from typing import Optional

KALI_TOOLS_URL = os.getenv("KALI_TOOLS_URL", "http://kali-tools:3800")
from orchestrator.hardening.timeout_guard import get_timeout_guard, TimeoutError as GuardTimeout
from orchestrator.hardening.rate_limiter import get_limiter


class KaliToolsClient:
    def __init__(self, base_url: str = KALI_TOOLS_URL):
        self.base_url = base_url
        self._guard = get_timeout_guard()
        self._limiter = get_limiter()

    async def run(self, tool: str, args: str = "", timeout: int = 300) -> dict:
        key = f"{tool}:{args[:60]}"
        await self._limiter.wait(key)
        try:
            actual_timeout = self._guard.get_timeout(f"kali_{tool}")
            effective_timeout = min(timeout, actual_timeout)
            async def _call():
                async with httpx.AsyncClient() as c:
                    resp = await c.post(
                        f"{self.base_url}/run",
                        params={"tool": tool, "args": args, "timeout": effective_timeout},
                        timeout=effective_timeout + 10,
                    )
                return resp.json()
            return await self._guard.run(key, _call(), timeout=effective_timeout + 5)
        except GuardTimeout:
            return {"error": f"kali-tools {tool} timed out ({timeout}s)", "tool": tool, "timeout": True}
        except httpx.ConnectError:
            return {"error": f"Cannot connect to kali-tools at {self.base_url}", "tool": tool}
        except Exception as e:
            return {"error": str(e), "tool": tool}

    async def run_impacket(self, script: str, args: str = "", timeout: int = 120) -> dict:
        tool_name = f"impacket-{script}"
        result = await self.run(tool_name, args, timeout=timeout)
        if result.get("returncode") is not None:
            return result
        return await self.run("python3", f"-m impacket.examples.{script} {args}", timeout=timeout)

    async def run_certipy(self, args: str = "", timeout: int = 120) -> dict:
        return await self.run("certipy", args, timeout=timeout)

    async def run_hashcat(self, args: str = "", timeout: int = 600) -> dict:
        return await self.run("hashcat", args, timeout=timeout)

    async def run_nuclei(self, target: str, templates: list = None,
                         severity: str = None, rate_limit: int = 50) -> dict:
        args = f"-u {target} -json -silent -rate-limit {rate_limit}"
        if templates:
            for t in templates:
                args += f" -t {t}"
        if severity:
            args += f" -severity {severity}"
        return await self.run("nuclei", args, timeout=600)

    async def run_sqlmap(self, url: str, args: str = "", timeout: int = 120) -> dict:
        return await self.run("sqlmap", f"-u {url} --batch --random-agent {args}", timeout=timeout)

    async def tools_list(self) -> list:
        try:
            async with httpx.AsyncClient() as c:
                resp = await c.get(f"{self.base_url}/tools", timeout=5)
                return resp.json().get("tools", [])
        except Exception:
            return []

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient() as c:
                resp = await c.get(f"{self.base_url}/health", timeout=5)
                return resp.json()
        except Exception as e:
            return {"status": "error", "detail": str(e)}


kali = KaliToolsClient()
