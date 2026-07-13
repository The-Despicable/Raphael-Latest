import asyncio, json, logging, re, time, socket

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.scanners.nmap_scanner import NmapScanner
from orchestrator.scanners.whatweb_scanner import WhatwebScanner
from orchestrator.scanners.nuclei_scanner import NucleiScanner
from orchestrator.scanners.masscan_wrapper import MasscanWrapper
from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
from orchestrator.scanners.enum4linux_wrapper import Enum4linuxWrapper, SmbmapWrapper
from orchestrator.scanners.dns_wrappers import DNSWrapper, WhoIsWrapper


def _grab_banner(host: str, port: int, timeout: float = 5.0) -> str:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        if port == 22:
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port in (80, 443, 8080, 8443, 8000, 8888):
            proto = "https" if port in (443, 8443) else "http"
            s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            resp = s.recv(4096).decode(errors="replace")
            s.close()
            for line in resp.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return ""
        elif port == 21:
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port == 25:
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port == 110:
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port == 143:
            s.sendall(b"a001 CAPABILITY\r\n")
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port == 3306:
            banner = s.recv(4096).decode(errors="replace", backslashreplace=True)
            s.close()
            return banner
        elif port == 6379:
            s.sendall(b"PING\r\n")
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port in (5900, 5901):
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        elif port in (5985, 5986):
            proto = "https" if port == 5986 else "http"
            s.sendall(f"GET /wsman HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            resp = s.recv(4096).decode(errors="replace")
            s.close()
            return resp[:200]
        elif port in (1515, 9100, 515):
            s.sendall(b"\x03archive_intake\r\n")
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
        else:
            banner = s.recv(4096).decode(errors="replace").strip()
            s.close()
            return banner
    except Exception:
        return ""


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:p\d+)?(?:-\w+)?)")


def _extract_version(text: str) -> str:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else ""


async def run_recon(target: str, nmap_scanner: NmapScanner = None,
                    whatweb_scanner: WhatwebScanner = None,
                    nuclei_scanner: NucleiScanner = None,
                    findings: list = None) -> PhaseResult:
    t0 = time.time()
    findings = []

    nmap = nmap_scanner or NmapScanner()
    whatweb = whatweb_scanner or WhatwebScanner()
    nuclei = nuclei_scanner or NucleiScanner()
    masscan = MasscanWrapper()
    gobuster = GobusterWrapper()
    enum4linux = Enum4linuxWrapper()
    smbmap = SmbmapWrapper()
    dns = DNSWrapper()
    whois = WhoIsWrapper()

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(target)
        findings.append(Finding(
            phase="recon", type="dns_resolution", target=target,
            description=f"{target} resolves to {resolved_ip}",
            evidence=resolved_ip,
        ))
    except socket.gaierror:
        pass

    ip = resolved_ip or target.split(":")[0]

    # Port scan: in-process nmap TCP connect (works from host with VPN)
    port_findings = []
    loop = asyncio.get_running_loop()
    try:
        scan_result = await loop.run_in_executor(
            None, nmap.scan_ports, target, "1-10000", 200
        )
        if "error" not in scan_result:
            port_findings = scan_result.get("ports", [])
            raw_output = f"nmap: {scan_result.get('port_count', 0)} open ports"
        else:
            raw_output = scan_result["error"]
    except Exception as e2:
        raw_output = f"scan error: {e2}"

    for p in port_findings:
        findings.append(Finding(
            phase="recon", type="open_port", target=target,
            host=ip, port=p["port"], protocol=p.get("protocol", "tcp"),
            service=p.get("service", "unknown"),
            severity=Severity.INFO,
            description=f"Port {p['port']}/{p.get('protocol', 'tcp')} open — {p.get('service','?')}",
        ))

    # Banner grabbing for version detection
    banner_results = {}
    for p in port_findings:
        port = p["port"]
        banner = await loop.run_in_executor(None, _grab_banner, ip, port)
        if banner:
            service = p.get("service", "unknown")
            banner_results[(ip, port)] = banner
            version = _extract_version(banner)
            findings.append(Finding(
                phase="recon", type="service_banner", target=target,
                host=ip, port=port, service=service,
                severity=Severity.INFO,
                description=f"Banner ({service}/{port}): {banner[:200]}",
                evidence=banner,
                raw={"version": version, "banner": banner[:500]},
            ))
            if version:
                findings.append(Finding(
                    phase="recon", type="service_version", target=target,
                    host=ip, port=port, service=service,
                    severity=Severity.INFO,
                    description=f"{service} {version} on port {port}",
                    evidence=version,
                ))
            raw_output += f" | banner:{port}"
    raw_output += f" | banners:{len(banner_results)}"

    # Web tech detection
    if any(f.service in ("http", "https") or (f.type == "open_port" and f.port in (80, 443, 8080, 8443)) for f in findings):

        try:
            web_result = await loop.run_in_executor(None, whatweb.scan, target)
            if "error" not in web_result:
                for tech, evidence in web_result.get("technologies", {}).items():
                    findings.append(Finding(
                        phase="recon", type="technology", target=target,
                        host=ip, severity=Severity.INFO,
                        description=f"Detected: {tech}",
                        evidence=str(evidence),
                    ))
                raw_output += f" | techs: {web_result.get('tech_count', 0)}"
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

    # DNS zone transfer + SRV records
    domain = target
    if "://" in domain:
        domain = domain.split("://")[1].split("/")[0]
    if "." in domain and not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        try:
            zt = await dns.zone_transfer(domain, timeout=30)
            if zt.get("count", 0) > 0:
                findings.append(Finding(
                    phase="recon", type="zone_transfer", target=target,
                    severity=Severity.HIGH,
                    description=f"DNS zone transfer succeeded: {zt['count']} records",
                    evidence="\n".join(zt["records"][:10]),
                ))
                raw_output += f" | zone_xfer: {zt['count']}"
            srv = await dns.srv_records(domain, timeout=30)
            if srv.get("count", 0) > 0:
                for rec in srv["records"]:
                    findings.append(Finding(
                        phase="recon", type="srv_record", target=target,
                        severity=Severity.INFO,
                        description=f"SRV: {rec}",
                    ))
                raw_output += f" | srv: {srv['count']}"
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

        try:
            wi = await whois.lookup(domain, timeout=30)
            if wi.get("registrant"):
                findings.append(Finding(
                    phase="recon", type="whois", target=target,
                    severity=Severity.INFO,
                    description="Whois: " + "; ".join(wi["registrant"][:3]),
                ))
            if wi.get("nameservers"):
                findings.append(Finding(
                    phase="recon", type="nameserver", target=target,
                    severity=Severity.INFO,
                    description=f"NS: {', '.join(wi['nameservers'][:5])}",
                ))
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

    # Gobuster DNS enumeration
    if "." in domain and not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        try:
            dns_result = await gobuster.dns(domain, timeout=60)
            for sub in dns_result.get("subdomains", []):
                findings.append(Finding(
                    phase="recon", type="subdomain", target=target,
                    host=ip, severity=Severity.INFO,
                    description=f"Subdomain: {sub}.{domain}",
                    evidence=sub,
                ))
            if dns_result.get("count", 0) > 0:
                raw_output += f" | subdomains: {dns_result['count']}"
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

    # Enum4linux SMB enumeration
    try:
        smb_result = await enum4linux.enum(ip, timeout=60)
        if smb_result.get("users"):
            for u in smb_result["users"]:
                findings.append(Finding(
                    phase="recon", type="smb_user", target=target,
                    host=ip, severity=Severity.MEDIUM,
                    description=f"SMB user: {u}",
                    evidence=u,
                ))
        if smb_result.get("shares"):
            for s in smb_result["shares"]:
                findings.append(Finding(
                    phase="recon", type="smb_share", target=target,
                    host=ip, severity=Severity.MEDIUM,
                    description=f"SMB share: {s}",
                    evidence=s,
                ))
        if smb_result.get("os_info"):
            findings.append(Finding(
                phase="recon", type="os_info", target=target,
                host=ip, severity=Severity.INFO,
                description=f"OS: {smb_result['os_info']}",
            ))
        if smb_result.get("users") or smb_result.get("shares"):
            raw_output += f" | smb: {len(smb_result.get('users',[]))} users, {len(smb_result.get('shares',[]))} shares"
    except Exception:
        logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

    latency = time.time() - t0
    return PhaseResult(
        phase="recon",
        success=len(findings) > 0,
        findings=findings,
        summary=f"Recon: {len(findings)} findings ({sum(1 for f in findings if f.port)} ports)",
        raw_output=raw_output,
        latency=latency,
    )
