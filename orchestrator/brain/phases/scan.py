import logging
import time, socket

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.scanners.nuclei_scanner import NucleiScanner
from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
from orchestrator.scanners.enum4linux_wrapper import SmbmapWrapper
from orchestrator.scanners.web_wrappers import NiktoWrapper, WfuzzWrapper
from orchestrator.brain.phases.recon import run_recon


async def run_scan(target: str, findings: list[Finding] = None,
                   nuclei_scanner: NucleiScanner = None,
                   skip_recon: bool = False,
                   nuclei_headers: dict = None) -> PhaseResult:
    t0 = time.time()

    if not skip_recon and not findings:
        recon = await run_recon(target)
        findings = recon.findings

    # Auto-detect vhost from reverse DNS if no custom headers provided
    if nuclei_headers is None:
        try:
            hostname = socket.gethostbyaddr(target)[0]
            if hostname != target:
                nuclei_headers = {"Host": hostname}
        except (socket.herror, socket.gaierror, OSError):
            pass

    nuclei = nuclei_scanner or NucleiScanner()
    gobuster = GobusterWrapper()
    smbmap = SmbmapWrapper()
    nikto = NiktoWrapper()
    wfuzz = WfuzzWrapper()
    scan_findings = list(findings or [])
    nuclei_output = ""
    extra_output = []

    if nuclei.available:
        try:
            result = await nuclei.scan(target, severity="info", headers=nuclei_headers)
            if "error" not in result:
                for nf in result.get("findings", []):
                    info = nf.get("info", {})
                    severity_raw = info.get("severity", "info")
                    severity_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    sev = severity_map.get(severity_raw.lower(), Severity.INFO)
                    cve_id = None
                    for ref in info.get("classification", {}).get("cve_id", []):
                        cve_id = ref
                        break
                    if not cve_id:
                        for ref in info.get("references", []):
                            if "cve" in ref.lower():
                                cve_id = ref.split("/")[-1]
                                break
                    matched = nf.get("matched-at", "")
                    port = None
                    if ":" in matched:
                        try:
                            port = int(matched.split(":")[-1].split("/")[0])
                        except (ValueError, IndexError):
                            pass
                    scan_findings.append(Finding(
                        phase="scan", type="vulnerability", target=target,
                        host=target, port=port, severity=sev, cve=cve_id,
                        description=info.get("name", severity_raw),
                        evidence=matched[:300], raw=nf,
                    ))
                nuclei_output = f"nuclei: {result.get('findings_count', 0)} findings"
            else:
                nuclei_output = f"nuclei: {result['error']}"
        except Exception as e:
            nuclei_output = f"nuclei error: {e}"
    else:
        nuclei_output = "nuclei not available"

    # Gobuster web directory busting on HTTP/HTTPS ports
    http_hosts = set()
    for f in scan_findings:
        if f.type == "open_port" and f.port in (80, 443, 8080, 8443, 8000, 8888):
            http_hosts.add((f.host or target, f.port))
    for host, port in http_hosts:
        proto = "https" if port in (443, 8443) else "http"
        url = f"{proto}://{host}:{port}"

        try:
            dir_result = await gobuster.dirs(url, timeout=120)
            for path in dir_result.get("paths", []):
                scan_findings.append(Finding(
                    phase="scan", type="discovered_path", target=target,
                    host=host, port=port, severity=Severity.MEDIUM,
                    description=f"Discovered: {url}/{path}",
                ))
            if dir_result.get("count", 0) > 0:
                extra_output.append(f"gobuster: {dir_result['count']} paths on {port}")
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

        try:
            nikto_result = await nikto.scan(url, timeout=180)
            for vuln in nikto_result.get("vulnerabilities", []):
                scan_findings.append(Finding(
                    phase="scan", type="nikto_finding", target=target,
                    host=host, port=port, severity=Severity.MEDIUM,
                    description=f"Nikto: {vuln[:200]}",
                ))
            if nikto_result.get("count", 0) > 0:
                extra_output.append(f"nikto: {nikto_result['count']} issues on {port}")
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

        try:
            wfuzz_result = await wfuzz.fuzz(f"{url}/FUZZ", timeout=120)
            for finding in wfuzz_result.get("findings", []):
                scan_findings.append(Finding(
                    phase="scan", type="wfuzz_finding", target=target,
                    host=host, port=port, severity=Severity.MEDIUM,
                    description=f"Wfuzz: {finding[0]} ({finding[1]})",
                ))
            if wfuzz_result.get("count", 0) > 0:
                extra_output.append(f"wfuzz: {wfuzz_result['count']} hits on {port}")
        except Exception:
            logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

    # SMB share scanning
    for f in scan_findings:
        if f.port == 445 or f.type == "smb_share":
            smb_host = f.host or target
            try:
                smb_result = await smbmap.scan(smb_host, timeout=60)
                writable = smb_result.get("writable", [])
                for share in writable:
                    scan_findings.append(Finding(
                        phase="scan", type="smb_writable", target=target,
                        host=smb_host, severity=Severity.HIGH,
                        description=f"Writable SMB share: {share}",
                        evidence=share,
                    ))
                if writable:
                    extra_output.append(f"smb: {len(writable)} writable shares on {smb_host}")
            except Exception:
                logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

            break

    latency = time.time() - t0
    new_findings = [f for f in scan_findings if f.phase == "scan"]
    extra = " | ".join(extra_output)
    summary_parts = [f"scan: {len(new_findings)} findings"]
    if extra:
        summary_parts.append(extra)
    return PhaseResult(
        phase="scan",
        success=len(new_findings) > 0,
        findings=scan_findings,
        summary=" | ".join(summary_parts),
        raw_output=f"{nuclei_output} | {extra}" if extra else nuclei_output,
        latency=latency,
    )
