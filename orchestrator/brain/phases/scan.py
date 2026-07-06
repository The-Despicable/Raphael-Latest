import time

from .models import Finding, PhaseResult, Severity
from ...scanners.nuclei_scanner import NucleiScanner
from .recon import run_recon


async def run_scan(target: str, findings: list[Finding] = None,
                   nuclei_scanner: NucleiScanner = None,
                   skip_recon: bool = False) -> PhaseResult:
    t0 = time.time()

    if not skip_recon and not findings:
        recon = await run_recon(target)
        findings = recon.findings

    nuclei = nuclei_scanner or NucleiScanner()

    # Extract URLs for nuclei scanning
    http_findings = [f for f in findings if f.service in ("http", "https", "http-proxy", "http-alt", "https-alt")]
    ports_with_http = set(f.port for f in http_findings if f.port)

    scan_findings = list(findings) if findings else []

    # Try nuclei against the target
    nuclei_output = ""
    if nuclei.available:
        try:
            result = nuclei.scan(target, severity="low")
            if "error" not in result:
                for nf in result.get("findings", []):
                    info = nf.get("info", {})
                    severity_raw = info.get("severity", "info")
                    severity_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    sev = severity_map.get(severity_raw, Severity.INFO)
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
                        except ValueError:
                            pass

                    scan_findings.append(Finding(
                        phase="scan", type="vulnerability", target=target,
                        host=target,
                        port=port,
                        severity=sev,
                        cve=cve_id,
                        description=info.get("name", severity_raw),
                        evidence=matched[:300],
                        raw=nf,
                    ))
                nuclei_output = f"nuclei: {result.get('findings_count', 0)} findings"
            else:
                nuclei_output = f"nuclei: {result['error']}"
        except Exception as e:
            nuclei_output = f"nuclei error: {e}"
    else:
        nuclei_output = "nuclei binary not available"

    latency = time.time() - t0
    new_findings = [f for f in scan_findings if f.phase == "scan"]
    return PhaseResult(
        phase="scan",
        success=len(new_findings) > 0,
        findings=scan_findings,
        summary=f"Scan complete: {len(new_findings)} vulnerabilities found",
        raw_output=nuclei_output,
        latency=latency,
    )
