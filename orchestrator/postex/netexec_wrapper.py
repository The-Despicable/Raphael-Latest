import subprocess, shutil, os, json
from typing import Optional

class NetExecWrapper:
    def __init__(self):
        self._binary = shutil.which("netexec") or shutil.which("nxc")
        self._source = "/tmp/NetExec"

    @property
    def available(self) -> bool:
        return self._binary is not None or os.path.exists(self._source + "/nxc/netexec.py")

    def smb_pth(self, target: str, username: str, hash: str,
                module: str = "shares") -> dict:
        cmd = self._build_cmd("smb", target, username=username, hash=hash, module=module)
        return self._run(cmd)

    def smb_enum(self, target: str, username: str = None,
                 password: str = None, hash: str = None) -> dict:
        cmd = self._build_cmd("smb", target, username=username,
                              password=password, hash=hash, module="shares")
        return self._run(cmd)

    def ldap_kerberoast(self, target: str, username: str, password: str) -> dict:
        cmd = self._build_cmd("ldap", target, username=username,
                              password=password, module="kerberoast")
        return self._run(cmd)

    def _build_cmd(self, protocol: str, target: str, **kwargs) -> list:
        cmd = ["python3", os.path.join(self._source, "nxc", "netexec.py")]
        cmd.extend([protocol, target])
        if kwargs.get("username"):
            cmd.extend(["-u", kwargs["username"]])
        if kwargs.get("password"):
            cmd.extend(["-p", kwargs["password"]])
        if kwargs.get("hash"):
            cmd.extend(["-H", kwargs["hash"]])
        if kwargs.get("module"):
            cmd.extend(["-M", kwargs["module"]])
        return cmd

    def _run(self, cmd: list) -> dict:
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{self._source}:{env.get('PYTHONPATH', '')}"
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
            return {
                "command": " ".join(cmd[:6]) + "...",
                "output": (r.stdout + r.stderr)[:2000],
                "success": r.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"error": "NetExec timed out"}
        except Exception as e:
            return self._simulate(cmd)

    def _simulate(self, cmd: list) -> dict:
        import re
        target = "unknown"
        for c in cmd:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', c):
                target = c
                break
        return {
            "target": target,
            "protocol": cmd[3] if len(cmd) > 3 else "unknown",
            "note": f"SIMULATED: {' '.join(cmd[:5])}...",
            "output": "[SIMULATED] NetExec would execute lateral movement against target",
        }
