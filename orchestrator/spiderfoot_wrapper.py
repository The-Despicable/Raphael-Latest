import os, sys, json, socket, subprocess, tempfile, re

SF_VENV = "/tmp/sf_venv"

_TARGET_RE = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$')


def _validate_target(target: str) -> str:
    if not _TARGET_RE.match(target):
        raise ValueError(f"Invalid target: {target!r}")
    return target


_SF_EXECUTOR = """import json, sys
with open(sys.argv[1]) as f:
    config = json.load(f)
action = config["action"]
target = config["target"]
if action == "dns":
    import dns.resolver
    qtype = config["qtype"]
    try:
        a = dns.resolver.resolve(target, qtype)
        for r in a:
            print(r)
    except Exception as e:
        sys.stderr.write(str(e))
elif action == "whois":
    import whois, json as j
    try:
        w = whois.whois(target)
        d = {k: str(v) for k, v in (w or {}).items() if v}
        print(j.dumps(d, indent=2))
    except Exception as e:
        print(str(e))
elif action == "email":
    import requests, re as _re
    try:
        r = requests.get(f'https://{target}', timeout=10, headers={})
        print(r.text[:50000])
    except Exception:
        pass
"""


class SpiderFootWrapper:
    def __init__(self):
        self._python = f"{SF_VENV}/bin/python3" if os.path.isfile(f"{SF_VENV}/bin/python3") else "python3"
        self._available = os.path.isdir(SF_VENV)
        self._executor = os.path.join(tempfile.gettempdir(), "_sf_executor.py")
        if not os.path.isfile(self._executor):
            with open(self._executor, "w") as f:
                f.write(_SF_EXECUTOR)

    def scan(self, target: str, modules: str = "dnsresolve,whois,subdomains") -> dict:
        if not self._available:
            return {"status": "unavailable", "note": "SpiderFoot venv not installed"}

        module_list = [m.strip() for m in modules.split(",")]
        results = {}

        if "dnsresolve" in module_list or "all" in module_list:
            results["dns"] = self._dns(target)
        if "whois" in module_list or "all" in module_list:
            results["whois"] = self._whois(target)
        if "subdomains" in module_list or "all" in module_list:
            results["subdomains"] = self._subdomains(target)
        if "email" in module_list or "all" in module_list:
            results["email"] = self._emails(target)

        return {"status": "ok", "target": target, "modules": module_list, "results": results}

    def _run_with_config(self, config: dict, timeout: int = 15) -> str:
        config_path = os.path.join(tempfile.gettempdir(), f"_sf_config_{os.getpid()}.json")
        with open(config_path, "w") as f:
            json.dump(config, f)
        try:
            r = subprocess.run(
                [self._python, self._executor, config_path],
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "PATH": f"{SF_VENV}/bin:" + os.environ.get("PATH", "")},
            )
            return r.stdout.strip() or r.stderr.strip()
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return str(e)
        finally:
            try:
                os.unlink(config_path)
            except OSError:
                pass

    def _dns(self, target: str) -> dict:
        _validate_target(target)
        records = {}
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            config = {"action": "dns", "target": target, "qtype": qtype}
            out = self._run_with_config(config, timeout=10)
            if out and out != "TIMEOUT" and "Can't find" not in out and "No answer" not in out:
                records[qtype] = out.split("\n")[:10]
        return records

    def _whois(self, target: str) -> dict:
        _validate_target(target)
        config = {"action": "whois", "target": target}
        out = self._run_with_config(config, timeout=20)
        if out and out != "TIMEOUT":
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return {"raw": out[:2000]}
        return {"error": "timeout or no data"}

    def _subdomains(self, target: str) -> dict:
        _validate_target(target)
        common = ["www", "mail", "admin", "api", "blog", "cdn", "dev", "staging", "test", "vpn"]
        found = []
        for sub in common:
            try:
                host = f"{sub}.{target}"
                ip = socket.gethostbyname(host)
                found.append({"subdomain": host, "ip": ip})
            except socket.gaierror:
                pass
        return {"method": "common_bruteforce", "subdomains": found}

    def _emails(self, target: str) -> dict:
        _validate_target(target)
        config = {"action": "email", "target": target}
        out = self._run_with_config(config, timeout=15)
        if out and out != "TIMEOUT":
            emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+", out)))
            domain_emails = [e for e in emails if target in e]
            return {"emails": domain_emails[:20], "all_emails": emails[:20]}
        return {"emails": []}

    def scan_cli(self, target: str, modules: str = "dnsresolve,whois,subdomains") -> dict:
        return self.scan(target, modules)
