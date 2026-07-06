import time
import socket

from .models import Finding, PhaseResult, Severity
from ...scanners.nmap_scanner import NmapScanner
from ...scanners.whatweb_scanner import WhatwebScanner
from ...scanners.nuclei_scanner import NucleiScanner


async def run_recon(target: str, nmap_scanner: NmapScanner = None,
                    whatweb_scanner: WhatwebScanner = None,
                    nuclei_scanner: NucleiScanner = None) -> PhaseResult:
    t0 = time.time()
    findings = []

    nmap = nmap_scanner or NmapScanner()
    whatweb = whatweb_scanner or WhatwebScanner()
    nuclei = nuclei_scanner or NucleiScanner()

    # 1. DNS resolution
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

    # 2. Port scan (top 1000)
    try:
        scan_result = nmap.scan_ports(target, ports="1-1000", rate=100)
        if "error" not in scan_result:
            for p in scan_result.get("ports", []):
                findings.append(Finding(
                    phase="recon", type="open_port", target=target,
                    host=resolved_ip or target,
                    port=p["port"], protocol=p.get("protocol", "tcp"),
                    service=p.get("service", "unknown"),
                    severity=Severity.INFO,
                    description=f"Port {p['port']}/{p['protocol']} — {p.get('service', 'unknown')}",
                    evidence=f"state: {p.get('state', 'open')}",
                ))
            raw_output = f"Open ports: {scan_result.get('port_count', 0)}"
        else:
            raw_output = scan_result["error"]
    except Exception as e:
        raw_output = f"nmap error: {e}"

    # 3. HTTP service detection (whatweb)
    if any(f.service in ("http", "https", "http-proxy", "http-alt", "https-alt") for f in findings):
        try:
            web_result = whatweb.scan(target)
            if "error" not in web_result:
                for tech, evidence in web_result.get("technologies", {}).items():
                    findings.append(Finding(
                        phase="recon", type="technology", target=target,
                        host=resolved_ip or target,
                        severity=Severity.INFO,
                        description=f"Detected: {tech}",
                        evidence=str(evidence),
                    ))
                raw_output += f" | Techs: {web_result.get('tech_count', 0)}"
        except Exception:
            pass

    latency = time.time() - t0
    return PhaseResult(
        phase="recon",
        success=len(findings) > 0,
        findings=findings,
        summary=f"Recon complete: {len(findings)} findings ({sum(1 for f in findings if f.port)} open ports)",
        raw_output=raw_output,
        latency=latency,
    )
