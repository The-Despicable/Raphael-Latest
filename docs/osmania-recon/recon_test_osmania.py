#!/usr/bin/env python3
"""
Raphael 2.0 — Test Recon Session: osmania.ac.in

⚠️  OPSEC POSTMORTEM — 26 June 2026
    This script was originally run with PROXY = None.
    Full source IP exposure to target.
    See ghost.md Appendix A for full postmortem.
    See proxy_guard.py for the mandatory enforcement layer.

    THE CORRECT WAY:
        from proxy_guard import guarded_operation
        with guarded_operation("osmania.ac.in") as pg:
            pg.get("https://target.com")
"""
import dns.resolver, dns.exception
import requests, json, sys, time, random, socket, ssl, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

# Add proxy_guard to path
sys.path.insert(0, "/home/yaser/Ultimate skill/raphael-2.0/orchestrator")

TARGET = "osmania.ac.in"
OUTPUT = "/home/yaser/Ultimate skill/recon-test-osmania-2026-06-26.txt"
TIMEOUT = 10
THREADS = 30
PROXY = None  # ← HISTORICAL MISTAKE. See ghost.md Appendix A.

results = {
    "target": TARGET,
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    "subdomains": {},
    "ips": {},
    "web_tech": {},
    "directories": {},
    "endpoints": {},
    "notes": []
}

def log(msg):
    print(f"[+] {msg}")
    results["notes"].append(msg)

def warn(msg):
    print(f"[!] {msg}")
    results["notes"].append(f"WARN: {msg}")

# ── Subdomain Discovery ──

def crt_sh(domain):
    """Fetch subdomains from crt.sh certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            subs = set()
            for entry in r.json():
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and "*" not in n:
                        subs.add(n)
            return sorted(subs)
    except Exception as e:
        warn(f"crt.sh error: {e}")
    return []

def dns_bruteforce(domain, wordlist=None):
    """DNS brute force subdomain enumeration"""
    if wordlist is None:
        wordlist = [
            "www", "mail", "webmail", "admin", "portal", "login", "vpn", "remote",
            "intranet", "hrms", "ums", "nertu", "cms", "erp", "sis", "lms",
            "exam", "results", "admissions", "library", "faculty", "student",
            "alumni", "research", "registrar", "finance", "accounts", "payroll",
            "helpdesk", "support", "ticket", "git", "jenkins", "jira", "confluence",
            "wiki", "blog", "news", "events", "placement", "tpo", "coe", "dcs",
            "dce", "dme", "ece", "cse", "it", "mba", "mca", "phd", "staff",
            "old", "test", "dev", "stage", "uat", "backup", "db", "sql",
            "api", "ws", "soap", "rest", "graphql", "app", "mobile",
            "moodle", "zoom", "teams", "outlook", "exchange", "owa", "autodiscover",
            "smtp", "pop3", "imap", "ftp", "sftp", "ssh", "rdp", "telnet",
            "monitor", "nagios", "zabbix", "cacti", "grafana", "kibana",
            "cloud", "cdn", "static", "assets", "img", "images", "media",
            "download", "upload", "files", "docs", "pdf", "forms", "survey",
            "chat", "forum", "community", "status", "info", "about", "contact",
        ]
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

    def check(sub):
        try:
            name = f"{sub}.{domain}"
            answers = resolver.resolve(name, 'A')
            ips = [str(r) for r in answers]
            return (name, ips, None)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return None
        except Exception as e:
            return (f"{sub}.{domain}", [], str(e))

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(check, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result and result[1]:
                found.append(result)
                log(f"Subdomain: {result[0]} → {', '.join(result[1])}")

    return found

# ── IP / Port Recon ──

def resolve_all(subdomains):
    """Resolve all found subdomains"""
    for name, ips, _ in subdomains:
        for ip in ips:
            if ip not in results["ips"]:
                results["ips"][ip] = []
            results["ips"][ip].append(name)

def common_ports_scan(ip, ports=None):
    """Quick TCP scan on common ports"""
    if ports is None:
        ports = [80, 443, 8080, 8443, 22, 21, 3389, 3306, 1433, 5432,
                 6379, 27017, 25, 465, 587, 110, 993, 995, 53, 161,
                 4444, 50050, 7443, 9090, 9000, 3000, 5000, 8000, 8888]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass
    return open_ports

# ── Web Fingerprinting ──

def fingerprint_url(url):
    """Get HTTP headers, status, tech signatures"""
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                         allow_redirects=True)
        info = {
            "status": r.status_code,
            "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "aspnet": r.headers.get("X-AspNet-Version", ""),
            "content_type": r.headers.get("Content-Type", ""),
            "location": r.headers.get("Location", ""),
            "cookies": list(r.cookies.keys()),
            "title": extract_title(r.text),
            "tech": [],
        }
        # Basic tech detection
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        if "php" in r.text[:500].lower(): info["tech"].append("PHP")
        if "asp.net" in headers_lower.get("x-powered-by", "").lower(): info["tech"].append("ASP.NET")
        if "iis" in headers_lower.get("server", "").lower(): info["tech"].append("IIS")
        if "nginx" in headers_lower.get("server", "").lower(): info["tech"].append("Nginx")
        if "apache" in headers_lower.get("server", "").lower(): info["tech"].append("Apache")
        if "tomcat" in headers_lower.get("server", "").lower(): info["tech"].append("Tomcat")
        if "cloudflare" in headers_lower.get("server", ""): info["tech"].append("Cloudflare")
        if "wordpress" in r.text[:2000].lower(): info["tech"].append("WordPress")
        if "drupal" in r.text[:2000].lower(): info["tech"].append("Drupal")
        if "jquery" in r.text[:5000].lower(): info["tech"].append("jQuery")
        if "bootstrap" in r.text[:5000].lower(): info["tech"].append("Bootstrap")
        if "react" in r.text[:5000].lower() or "react" in r.text[:5000]: info["tech"].append("React")

        return info
    except requests.exceptions.SSLError:
        return {"status": "SSL_ERROR"}
    except requests.ConnectionError:
        return {"status": "CONN_REFUSED"}
    except Exception as e:
        return {"status": f"ERROR: {e}"}

def extract_title(html):
    import re
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    return m.group(1).strip() if m else ""

# ── Directory Discovery ──

def discover_dirs(base_url, wordlist=None):
    """Check common paths"""
    if wordlist is None:
        wordlist = [
            "/admin", "/login", "/wp-admin", "/wp-login", "/administrator",
            "/res07/", "/Secure/", "/api", "/v1", "/v2", "/graphql",
            "/.env", "/.git/config", "/config", "/backup", "/db",
            "/phpinfo.php", "/info.php", "/test.php", "/shell",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/LoginSer.asmx", "/Service.asmx", "/WebService.asmx",
            "/ws", "/soap", "/rest", "/odata",
            "/swagger", "/swagger-ui", "/api/docs", "/openapi.json",
            "/actuator", "/actuator/health", "/actuator/info",
            "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
            "/console", "/manager", "/manager/html",
            "/upload", "/uploads", "/download", "/downloads",
            "/assets", "/static", "/img", "/images", "/css", "/js",
            "/.well-known/security.txt",
        ]
    found = []
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    def check(path):
        url = base_url.rstrip("/") + path
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in [200, 301, 302, 401, 403, 405, 500]:
                return (path, r.status_code, len(r.content))
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(check, p): p for p in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return found

# ── Run ──

def main():
    print(f"\n{'='*60}")
    print(f"  RAPHAEL 2.0 — TEST RECON: {TARGET}")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"  THIS IS A TEST RUN — NOT FULL DEPTH")
    print(f"{'='*60}\n")

    requests.packages.urllib3.disable_warnings()

    # Step 1: crt.sh
    log("Querying crt.sh certificate transparency logs...")
    crt_subs = crt_sh(TARGET)
    log(f"Found {len(crt_subs)} subdomains via crt.sh")

    # Step 2: DNS brute force
    log("Running DNS brute force (90+ words)...")
    dns_found = dns_bruteforce(TARGET)

    # Step 3: Merge results
    all_subs = {}
    for name, ips, _ in dns_found:
        all_subs[name] = ips
    for sub in crt_subs:
        if sub not in all_subs:
            try:
                answers = dns.resolver.resolve(sub, 'A')
                all_subs[sub] = [str(r) for r in answers]
            except:
                all_subs[sub] = ["(unresolved)"]

    results["subdomains"] = all_subs

    # Step 4: Resolve and group by IP
    log("Mapping subdomains to IPs...")
    for name, ips in all_subs.items():
        for ip in ips:
            if "(unresolved)" not in ip:
                if ip not in results["ips"]:
                    results["ips"][ip] = []
                results["ips"][ip].append(name)

    log(f"Unique IPs: {len(results['ips'])}")

    # Step 5: Port scan each unique IP
    log("Port scanning unique IPs (common ports)...")
    for ip in results["ips"]:
        ports = common_ports_scan(ip)
        if ports:
            log(f"  {ip}: open ports {ports}")
            results["ips"][ip] = {"subdomains": results["ips"][ip], "ports": ports}
        else:
            results["ips"][ip] = {"subdomains": results["ips"][ip], "ports": []}

    # Step 6: Web fingerprinting
    log("Fingerprinting web services...")
    web_targets = set()
    for name in all_subs:
        for proto in ["https://", "http://"]:
            web_targets.add(f"{proto}{name}")
    for ip in results["ips"]:
        info = results["ips"][ip]
        if 80 in info.get("ports", []) or 443 in info.get("ports", []):
            for proto in ["https://", "http://"]:
                web_targets.add(f"{proto}{ip}")
        if 8080 in info.get("ports", []):
            web_targets.add(f"http://{ip}:8080")
        if 8443 in info.get("ports", []):
            web_targets.add(f"https://{ip}:8443")

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(fingerprint_url, url): url for url in sorted(web_targets)}
        for future in as_completed(futures):
            url = futures[future]
            info = future.result()
            results["web_tech"][url] = info
            if info.get("status") not in ["CONN_REFUSED", "SSL_ERROR"] and not str(info.get("status", "")).startswith("ERROR"):
                log(f"  {url} → {info.get('status')} [{info.get('server')}] title: {info.get('title', '')[:60]}")

    # Step 7: Directory discovery on live web apps
    log("Directory discovery on live endpoints...")
    live_urls = [u for u, info in results["web_tech"].items()
                 if isinstance(info, dict) and info.get("status") in [200, 301, 302, 401, 403]]
    for url in live_urls[:5]:  # Limit to 5 to not go too deep
        dirs = discover_dirs(url)
        if dirs:
            results["directories"][url] = sorted(dirs)
            log(f"  {url}: found {len(dirs)} paths")

    # Step 8: Specific deeper probes on known endpoints from phase0
    log("Probing previously known endpoints...")
    known_endpoints = [
        "https://nertu.osmania.ac.in/res07/20250403.jsp?id=1",
        "http://14.139.82.42:8080/manager/html",
        "http://14.139.82.42:8080/examples/",
        "http://14.139.82.42:8080/docs/",
        "https://ums.osmania.ac.in/",
        "https://nertu.osmania.ac.in/LoginSer.asmx",
        "https://nertu.osmania.ac.in/Secure/ForgetPwd.aspx",
    ]
    for url in known_endpoints:
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"},
                             allow_redirects=False)
            results["endpoints"][url] = {"status": r.status_code, "len": len(r.content)}
            log(f"  {url} → {r.status_code} ({len(r.content)} bytes)")
        except Exception as e:
            results["endpoints"][url] = {"error": str(e)}
            warn(f"  {url} → {e}")

    # ── Write output ──
    print(f"\n{'='*60}")
    print(f"  WRITING RESULTS TO: {OUTPUT}")
    print(f"{'='*60}\n")

    with open(OUTPUT, "w") as f:
        f.write(f"RAPHAEL 2.0 — TEST RECON: {TARGET}\n")
        f.write(f"Date: {results['timestamp']}\n")
        f.write(f"Note: Test run — limited depth. Full recon when Raphael 2.0 is ready.\n\n")

        f.write(f"SUBODMAINS FOUND ({len(all_subs)}):\n")
        f.write(f"{'─'*60}\n")
        for name, ips in sorted(all_subs.items()):
            f.write(f"  {name} → {', '.join(ips)}\n")

        f.write(f"\n\nOPEN PORTS BY IP:\n")
        f.write(f"{'─'*60}\n")
        for ip, info in sorted(results["ips"].items()):
            ports = info.get("ports", [])
            if ports:
                f.write(f"  {ip} ({', '.join(info['subdomains'])}): {ports}\n")
            else:
                f.write(f"  {ip} ({', '.join(info['subdomains'])}): (standard ports closed or filtered)\n")

        f.write(f"\n\nWEB FINGERPRINTS:\n")
        f.write(f"{'─'*60}\n")
        for url, info in sorted(results["web_tech"].items()):
            status = info.get("status")
            if status not in ["CONN_REFUSED", "SSL_ERROR"] and not str(status).startswith("ERROR"):
                f.write(f"  {url}\n")
                f.write(f"    Status: {status}\n")
                f.write(f"    Server: {info.get('server', '')}\n")
                f.write(f"    Title: {info.get('title', '')[:80]}\n")
                if info.get("tech"):
                    f.write(f"    Tech: {', '.join(info['tech'])}\n")
                f.write("\n")

        f.write(f"\n\nDIRECTORIES FOUND:\n")
        f.write(f"{'─'*60}\n")
        for url, dirs in sorted(results["directories"].items()):
            f.write(f"  {url}:\n")
            for path, status, size in sorted(dirs):
                f.write(f"    {path} → {status} ({size} bytes)\n")

        f.write(f"\n\nENDPOINT PROBES:\n")
        f.write(f"{'─'*60}\n")
        for url, info in sorted(results["endpoints"].items()):
            f.write(f"  {url}\n")
            for k, v in info.items():
                f.write(f"    {k}: {v}\n")

        f.write(f"\n\nNOTES:\n")
        f.write(f"{'─'*60}\n")
        for note in results["notes"]:
            f.write(f"  {note}\n")

    print(f"[✓] Results written to: {OUTPUT}")
    print(f"[✓] Subdomains found: {len(all_subs)}")
    print(f"[✓] Unique IPs found: {len(results['ips'])}")
    print(f"[✓] Web endpoints fingerprinted: {len([x for x in results['web_tech'].values() if x.get('status') not in ['CONN_REFUSED', 'SSL_ERROR']])}")
    print(f"[✓] Open ports found: {sum(1 for v in results['ips'].values() if v.get('ports'))}")
    print()

if __name__ == "__main__":
    main()
