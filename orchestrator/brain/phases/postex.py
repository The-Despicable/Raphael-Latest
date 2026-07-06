import time

from .models import Finding, PhaseResult, Severity
from ...postex.winrm_exploit import WinRMExploit
from ...postex.bloodhound_integration import BloodHoundIntegration


async def run_postex(target: str, findings: list[Finding] = None,
                     winrm: WinRMExploit = None,
                     bloodhound: BloodHoundIntegration = None) -> PhaseResult:
    t0 = time.time()
    postex_findings = []

    # Check for WinRM ports
    has_winrm = any(f.port in (5985, 5986) for f in (findings or []) if f.port)

    if has_winrm:
        winrm_exploit = winrm or WinRMExploit()
        try:
            result = winrm_exploit.connect(target, username="", password="")
            if not result.get("error"):
                postex_findings.append(Finding(
                    phase="postex", type="winrm_access", target=target,
                    severity=Severity.CRITICAL,
                    description="WinRM accessible",
                    evidence=str(result)[:500],
                ))
        except Exception:
            pass

    latency = time.time() - t0
    return PhaseResult(
        phase="postex",
        success=len(postex_findings) > 0,
        findings=postex_findings,
        summary=f"Post-ex check: {len(postex_findings)} findings",
        raw_output=f"winrm: {'found' if has_winrm else 'not exposed'}",
        latency=latency,
    )
