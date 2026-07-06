import subprocess, json, time, os, re

SUBFINDER = os.getenv("SUBFINDER_PATH", "subfinder")
NMAP = os.getenv("NMAP_PATH", "nmap")
WHATWEB = os.getenv("WHATWEB_PATH", "whatweb")
DNS_RECON = os.getenv("DNS_RECON_PATH", "dnsrecon")


def _run(cmd: list, timeout: int = 120) -> tuple:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"


def passive_recon(target: str) -> dict:
    profile = {"target": target, "timestamp": time.time(), "subdomains": [], "dns": {}, "tech_stack": [], "ports": []}

    rc, out, err = _run([SUBFINDER, "-d", target, "-silent"], timeout=60)
    if rc == 0 and out.strip():
        profile["subdomains"] = [s.strip() for s in out.strip().split("\n") if s.strip()]

    rc, out, err = _run(["dig", "+short", target, "ANY"], timeout=15)
    if rc == 0 and out.strip():
        profile["dns"]["records"] = [r.strip() for r in out.strip().split("\n") if r.strip()]

    rc, out, err = _run([WHATWEB, target, "--color=never"], timeout=30)
    if rc == 0 and out.strip():
        profile["tech_stack"] = [t.strip() for t in out.strip().split(",") if t.strip()]

    rc, out, err = _run(
        [NMAP, "-sV", "-T4", "--top-ports", "100", "-Pn", target, "-oX", "-"],
        timeout=180,
    )
    if rc == 0 and out.strip():
        ports = []
        for m in re.finditer(r'portid="(\d+)"[^>]*protocol="(\w+)"[^>]*state="(\w+)"', out):
            ports.append({"port": int(m.group(1)), "proto": m.group(2), "state": m.group(3)})
        for m in re.finditer(r'service name="([^"]*)"[^>]*portid="(\d+)"', out):
            for p in ports:
                if p["port"] == int(m.group(2)):
                    p["service"] = m.group(1)
        profile["ports"] = ports
    elif rc == 0:
        rc2, out2, _ = _run(
            [NMAP, "-sV", "-T4", "--top-ports", "100", "-Pn", target],
            timeout=180,
        )
        if rc2 == 0 and out2:
            for line in out2.split("\n"):
                m = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)", line)
                if m:
                    profile["ports"].append({
                        "port": int(m.group(1)),
                        "proto": m.group(2),
                        "state": m.group(3),
                        "service": m.group(4),
                    })

    return profile


def classify_target(profile: dict) -> dict:
    ports = profile.get("ports", [])
    tech = profile.get("tech_stack", [])
    subs = profile.get("subdomains", [])

    classification = {"criticality": "medium", "sector": "unknown", "attack_surface": "moderate", "recommended_phases": []}

    web_ports = {80, 443, 8080, 8443, 8000, 3000}
    db_ports = {3306, 5432, 1433, 27017, 6379}
    ad_ports = {88, 389, 636, 445}

    has_web = any(p.get("port") in web_ports for p in ports)
    has_db = any(p.get("port") in db_ports for p in ports)
    has_ad = any(p.get("port") in ad_ports for p in ports)

    if has_web:
        classification["recommended_phases"].extend(["recon", "scan", "exploit"])
    if has_db:
        classification["recommended_phases"].extend(["scan", "exploit", "exfil"])
    if has_ad:
        classification["recommended_phases"].extend(["postex"])
    if len(subs) > 10:
        classification["attack_surface"] = "large"
        classification["recommended_phases"].append("phish")

    port_count = len(ports)
    if port_count > 20:
        classification["attack_surface"] = "large"
        classification["criticality"] = "high"
    elif port_count > 5:
        classification["attack_surface"] = "moderate"
    else:
        classification["attack_surface"] = "small"
        classification["criticality"] = "low"

    seen = set()
    classification["recommended_phases"] = [p for p in classification["recommended_phases"] if not (p in seen or seen.add(p))]

    return classification


def profile_target(target: str) -> dict:
    profile = passive_recon(target)
    classification = classify_target(profile)
    profile["classification"] = classification
    return profile


class TargetProfiler:
    def profile(self, target: str) -> dict:
        return profile_target(target)

    def classify(self, profile: dict) -> dict:
        return classify_target(profile)
