import os, subprocess, json, shutil

KARMA_DIR = "/tmp/karma_v2"
KARMA_SCRIPT = f"{KARMA_DIR}/karma_v2"


class KarmaV2Wrapper:
    def __init__(self):
        self._available = os.path.isfile(KARMA_SCRIPT)
        self._shodan_cli = shutil.which("shodan") is not None
        self._has_api_key = "SHODAN_API_KEY" in os.environ or os.path.isfile(os.path.expanduser("~/.shodan/api_key"))

    def scan(self, target: str, mode: str = "host") -> dict:
        if not self._available:
            return {"status": "unavailable", "note": f"git clone https://github.com/Dheerajmadhukar/karma_v2 {KARMA_DIR}"}

        if not self._shodan_cli or not self._has_api_key:
            return {
                "status": "requires_shodan_premium",
                "note": "karma_v2 requires Shodan Premium API key and CLI",
                "setup": "pip install shodan && shodan init YOUR_API_KEY",
                "fallback": "Use Raphael osint mode instead: python3 app.py osint <target>",
            }

        try:
            cmd = ["bash", KARMA_SCRIPT, "-d", target]
            if mode == "deep":
                cmd.extend(["--limit", "-1", "-deep"])
            else:
                cmd.extend(["--limit", "10"])

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=KARMA_DIR)
            output = (r.stdout + r.stderr)[-3000:]

            results = {"status": "ok", "target": target, "mode": mode}
            lines = output.split("\n")
            for line in lines:
                if "IP:" in line or "port:" in line or "CVE" in line.upper():
                    results.setdefault("findings", []).append(line.strip())

            if not results.get("findings"):
                results["raw_output"] = output[:2000]
            return results

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "note": "scan exceeded 120s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
