import time, socket

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.scanners.nmap_scanner import NmapScanner
from orchestrator.scanners.whatweb_scanner import WhatwebScanner
from orchestrator.scanners.nuclei_scanner import NucleiScanner
from orchestrator.scanners.masscan_wrapper import MasscanWrapper
from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
from orchestrator.scanners.enum4linux_wrapper import Enum4linuxWrapper, SmbmapWrapper
from orchestrator.scanners.dns_wrappers import DNSWrapper, WhoIsWrapper


async def run_recon(target: str, nmap_scanner: NmapScanner = None,
                    whatweb_scanner: WhatwebScanner = None,
                    nuclei_scanner: NucleiScanner = None) -> PhaseResult:
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

    # Masscan: fast port scan (1-10000)
    try:
        mass_result = await masscan.scan(ip, ports="1-10000", timeout=180)
        if mass_result.get("port_count", 0) > 0:
            for p in mass_result.get("ports", []):
                findings.append(Finding(
                    phase="recon", type="open_port", target=target,
                    host=ip, port=p["port"], protocol=p.get("protocol", "tcp"),
                    severity=Severity.INFO,
                    description=f"Port {p['port']}/{p['protocol']} open",
                ))
            raw_output = f"masscan: {mass_result['port_count']} open ports"
        else:
            raw_output = "masscan: no open ports found"
    except Exception as e:
        try:
            scan_result = nmap.scan_ports(target, ports="1-1000", rate=100)
            if "error" not in scan_result:
                for p in scan_result.get("ports", []):
                    findings.append(Finding(
                        phase="recon", type="open_port", target=target,
                        host=ip, port=p["port"], protocol=p.get("protocol", "tcp"),
                        service=p.get("service", "unknown"),
                        severity=Severity.INFO,
                        description=f"Port {p['port']}/{p['protocol']} — {p.get('service', 'unknown')}",
                    ))
                raw_output = f"nmap: {scan_result.get('port_count', 0)} open ports"
            else:
                raw_output = scan_result["error"]
        except Exception as e2:
            raw_output = f"scan error: {e2}"

    # Web tech detection
    if any(f.service in ("http", "https") or f.port in (80, 443, 8080, 8443) for f in findings):
        try:
            web_result = whatweb.scan(target)
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
            pass

    # DNS zone transfer + SRV records
    domain = target
    if "://" in domain:
        domain = domain.split("://")[1].split("/")[0]
    if "." in domain and not domain[-1].isdigit():
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
            pass

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
            pass

    # Gobuster DNS enumeration
    if "." in domain and not domain[-1].isdigit():
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
            pass

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
        pass

    latency = time.time() - t0
    return PhaseResult(
        phase="recon",
        success=len(findings) > 0,
        findings=findings,
        summary=f"Recon: {len(findings)} findings ({sum(1 for f in findings if f.port)} ports)",
        raw_output=raw_output,
        latency=latency,
    )
