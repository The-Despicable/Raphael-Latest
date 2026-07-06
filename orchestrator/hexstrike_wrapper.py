import os, subprocess, json, requests, time, signal, sys

HEXSTRIKE_DIR = "/tmp/hexstrike-ai"
API_PORT = 8888
API_URL = f"http://127.0.0.1:{API_PORT}"


class HexStrikeWrapper:
    def __init__(self):
        self.server_proc = None
        self._available = os.path.isdir(HEXSTRIKE_DIR)

    def list_tools_api(self) -> dict:
        try:
            r = requests.get(f"{API_URL}/tools", timeout=5)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    def execute_tool(self, tool: str, target: str, params: dict = None) -> dict:
        payload = {"tool": tool, "target": target, **(params or {})}
        try:
            r = requests.post(f"{API_URL}/execute", json=payload, timeout=120)
            return r.json()
        except Exception as e:
            return {"error": str(e), "tool": tool, "target": target}

    def generate_commands(self, target: str, tool: str = "nmap") -> dict:
        available_tools = {
            "nmap": {"install": "apt install nmap or use Raphael scanner pipeline", "params": "-sV -sC"},
            "nuclei": {"install": "nuclei binary at ~/.local/bin/nuclei", "params": "-severity medium"},
            "gobuster": {"install": "go install github.com/OJ/gobuster/v3@latest", "params": "dir -w /usr/share/wordlists/dirb/common.txt"},
            "sqlmap": {"install": "python3 /tmp/sqlmap/sqlmap.py", "params": "--batch --level=1 --risk=1"},
            "amass": {"install": "go install github.com/owasp-amass/amass/v4/...@master", "params": "enum"},
            "subfinder": {"install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "params": ""},
            "ffuf": {"install": "go install github.com/ffuf/ffuf@latest", "params": "-w /usr/share/wordlists/dirb/common.txt"},
            "nikto": {"install": "perl nikto.pl or docker", "params": "-h"},
            "enum4linux": {"install": "apt install enum4linux or use Raphael postex pipeline", "params": "-a"},
            "smbmap": {"install": "pip install smbmap", "params": "-H"},
            "rustscan": {"install": "docker pull rustscan/rustscan", "params": "-a"},
        }

        if tool == "list":
            return {"available_tools": list(available_tools.keys())}

        info = available_tools.get(tool, {"install": "unknown", "params": ""})
        return {
            "tool": tool,
            "target": target,
            "command": f"{tool} {info['params']} {target}",
            "install": info["install"],
            "alternative": "Use Raphael built-in pipeline instead",
            "raphael_command": self._raphael_equivalent(tool, target),
        }

    def _raphael_equivalent(self, tool: str, target: str) -> str:
        mapping = {
            "nmap": f"python3 app.py scan {target}",
            "nuclei": f"python3 app.py scan {target} --nuclei-severity medium",
            "sqlmap": f"python3 app.py exploit {target} --url http://{target}",
            "gobuster": f"ffuf or dirsearch (install separately)",
            "enum4linux": f"python3 app.py postex {target} --domain LOCAL --username guest",
            "smbmap": f"python3 app.py postex {target} --domain LOCAL",
            "nikto": f"nuclei with web templates (python3 app.py scan {target} --nuclei-severity medium)",
            "amass": f"subfinder (install separately)",
            "subfinder": f"install: go install ...",
            "ffuf": f"install: go install ...",
            "rustscan": f"nmap via Raphael scan pipeline",
        }
        return mapping.get(tool, f"python3 app.py exploit {target}")

    def security_tool_orchestration(self, task: str, target: str, tools: list = None) -> dict:
        return {
            "task": task,
            "target": target,
            "tools": tools or ["nmap", "nuclei"],
            "steps": [
                {"tool": t, "command": self._raphael_equivalent(t, target)}
                for t in (tools or ["nmap", "nuclei"])
            ],
            "note": "hexstrike-ai MCP server not running. Use Raphael pipeline directly.",
        }


RAPHAEL_TOOLS = {
    "nuclei": {"binary": os.path.expanduser("~/.local/bin/nuclei"), "raphel_cmd": "scan", "phase": 1},
    "sqlmap": {"binary": "/tmp/sqlmap/sqlmap.py", "raphel_cmd": "exploit", "phase": 2},
    "nmap": {"raphel_cmd": "scan", "phase": 1, "native": True},
}
