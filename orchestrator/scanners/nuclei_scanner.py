import json, shutil, subprocess, tempfile
from typing import Optional
from ..proxy_guard import ProxyGuard

class NucleiScanner:
    def __init__(self, pg: ProxyGuard = None):
        self.pg = pg
        self._binary = shutil.which("nuclei")

    @property
    def available(self) -> bool:
        return self._binary is not None

    def scan(self, target: str, templates: list = None,
             severity: str = None, rate_limit: int = 50) -> dict:
        if not self.available:
            return {"error": "nuclei not installed", "target": target}

        cmd = [self._binary, "-u", target,
               "-json", "-silent",
               "-rate-limit", str(rate_limit)]

        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        if severity:
            cmd.extend(["-severity", severity])

        if self.pg:
            self.pg._enforce_timing()

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            findings = []
            for line in r.stdout.strip().split("\n"):
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
        except subprocess.TimeoutExpired:
            return {"error": "nuclei scan timed out", "target": target}
        except Exception as e:
            return {"error": str(e), "target": target}
