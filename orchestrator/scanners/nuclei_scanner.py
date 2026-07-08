import json, shutil
from typing import Optional
from ..proxy_guard import ProxyGuard

KALI_TOOLS_URL = "http://kali-tools:3800"

class NucleiScanner:
    def __init__(self, pg: ProxyGuard = None):
        self.pg = pg

    @property
    def available(self) -> bool:
        return True

    def scan(self, target: str, templates: list = None,
             severity: str = None, rate_limit: int = 50) -> dict:
        args = f"-u {target} -json -silent -rate-limit {rate_limit}"

        if templates:
            for t in templates:
                args += f" -t {t}"
        if severity:
            args += f" -severity {severity}"

        if self.pg:
            self.pg._enforce_timing()

        try:
            import httpx
            resp = httpx.post(
                f"{KALI_TOOLS_URL}/run",
                params={"tool": "nuclei", "args": args, "timeout": 600},
                timeout=610
            )
            result = resp.json()
            if result.get("returncode") != 0:
                return {"error": result.get("stderr", "nuclei failed"), "target": target}

            findings = []
            for line in result["stdout"].strip().split("\n"):
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return {
                "target": target,
                "findings": findings,
                "findings_count": len(findings),
            }
        except Exception as e:
            return {"error": str(e), "target": target}
