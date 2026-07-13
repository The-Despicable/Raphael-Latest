"""
honeypot_analyzer.py — Source code analysis & honeypot detection.

Analyzes service binaries and source code for:
1. Honeypot detection (fake services, credential traps, monitoring)
2. Trigger condition analysis (what input triggers credential delivery)
3. Socket path discovery (Unix domain sockets)
4. Service logic extraction (auth bypasses, backdoors)
"""

import asyncio
import logging
import os
import re
import tempfile
import time
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_honeypot_analyzer")

HONEYPOT_INDICATORS = [
    r"(?i)honeypot",
    r"(?i)decoy",
    r"(?i)scan_for_malice",
    r"(?i)malicious",
    r"(?i)trap",
    r"(?i)credential.*delivery",
    r"(?i)admin.*password.*send",
    r"(?i)fake.*service",
    r"(?i)system_clean",
    r"(?i)monitor.*connection",
    r"(?i)log.*connection",
    r"(?i)SCM_RIGHTS",
    r"(?i)SCM_CREDENTIALS",
    r"(?i)pass.*fd",
    r"(?i)send.*credential",
    r"(?i)FSUPLOAD",
    r"(?i)FSDOWNLOAD",
    r"(?i)FSQUERY",
    r"(?i)PJL.*log",
    r"(?i)jetdirect",
    r"(?i)paperwork.?daemon",
]

TRIGGER_KEYWORDS = [
    "FSUPLOAD",
    "FSDOWNLOAD",
    "FSQUERY",
    "USTATUS",
    "FSUPLOAD",
    "FSDOWNLOAD",
]

SOCKET_PATTERNS = [
    r'(?i)socket\.(AF_UNIX|AF_UNIX|AF_LOCAL)',
    r'/var/run/[\w/-]+\.sock',
    r'/tmp/[\w/-]+\.sock',
    r'/run/[\w/-]+\.sock',
]

CRED_PATTERNS = [
    r"(?i)admin.*password\s*[=:]\s*['\"]?(\w+)['\"]?",
    r"(?i)password\s*=\s*['\"](\w+)['\"]",
    r"(?i)send.*credential",
    r"(?i)credential.*=.*\{",
]


def analyze_source(source: str, source_path: str = "") -> list[dict]:
    """
    Analyze binary or source code for honeypot indicators, credential flows,
    socket paths, and trigger conditions. Returns list of analysis results.
    """
    results = []
    if not source or len(source) < 50:
        return results

    lines = source.split("\n")
    source_lower = source.lower()

    # Check for honeypot indicators
    for pattern in HONEYPOT_INDICATORS:
        matches = list(re.finditer(pattern, source))
        if matches:
            context_lines = []
            for m in matches[:3]:
                line_no = source[:m.start()].count("\n") + 1
                start = max(0, m.start() - 50)
                end = min(len(source), m.end() + 100)
                context = source[start:end].replace("\n", " ")
                context_lines.append(f"  Line {line_no}: ...{context}...")
            results.append({
                "type": "honeypot_indicator",
                "pattern": pattern if isinstance(pattern, str) else pattern.pattern,
                "matches": len(matches),
                "context": "\n".join(context_lines),
                "severity": Severity.CRITICAL,
            })

    # Check for trigger condition keywords
    trigger_found = []
    for kw in TRIGGER_KEYWORDS:
        if kw.lower() in source_lower:
            trigger_found.append(kw)
    if trigger_found:
        results.append({
            "type": "trigger_condition",
            "keywords": trigger_found,
            "context": f"Source contains trigger keywords: {', '.join(trigger_found)}",
            "severity": Severity.CRITICAL,
        })

    # Extract socket paths
    socket_paths = set()
    for pattern in SOCKET_PATTERNS:
        for m in re.finditer(pattern, source):
            path = m.group(0)
            if path.startswith("socket."):
                continue
            socket_paths.add(path)
    if socket_paths:
        results.append({
            "type": "socket_paths",
            "paths": list(socket_paths),
            "context": f"Socket paths found: {', '.join(socket_paths)}",
            "severity": Severity.HIGH,
        })

    # Extract credential flows
    for pattern in CRED_PATTERNS:
        matches = list(re.finditer(pattern, source))
        if matches:
            creds_found = []
            for m in matches[:5]:
                if m.groups():
                    creds_found.append(m.group(1))
            results.append({
                "type": "credential_flow",
                "pattern": pattern if isinstance(pattern, str) else pattern.pattern,
                "values": creds_found,
                "context": f"Credential flow pattern: {pattern if isinstance(pattern, str) else pattern.pattern}",
                "severity": Severity.CRITICAL,
            })

    # Check for SCM_RIGHTS usage
    if "SCM_RIGHTS" in source or "scm_rights" in source_lower:
        results.append({
            "type": "scm_rights",
            "context": "Service uses SCM_RIGHTS for file descriptor passing",
            "severity": Severity.CRITICAL,
        })

    # Check for systemd restart behavior
    if "Restart=on-failure" in source or "Restart=always" in source:
        results.append({
            "type": "service_restart",
            "context": "Service configured for auto-restart on failure",
            "severity": Severity.HIGH,
        })

    # Automatic analysis of function structure
    func_defs = re.findall(r'(?:def |async def )(\w+)', source)
    if func_defs:
        interesting_funcs = [f for f in func_defs if any(
            kw in f.lower() for kw in ["scan", "malice", "check", "validate",
                                       "auth", "credential", "honeypot",
                                       "monitor", "log", "dispatch"]
        )]
        if interesting_funcs:
            results.append({
                "type": "interesting_functions",
                "functions": interesting_funcs,
                "context": f"Functions found: {', '.join(interesting_funcs)}",
                "severity": Severity.MEDIUM,
            })

    return results


async def analyze_remote_service(target: str, findings: list[Finding]) -> list[Finding]:
    """Analyze source code retrieved via prior exploit phases."""
    analysis_findings = []

    for f in findings:
        if f.type != "pjl_honeypot_source":
            continue

        source = f.evidence
        if not source or len(source) < 100:
            continue

        logger.info(f"  [Honeypot Analyzer] Analyzing {len(source)} bytes of source code")
        results = analyze_source(source)

        for r in results:
            rtype = r["type"]
            severity = r["severity"]

            if rtype == "honeypot_indicator":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="honeypot_confirmed",
                    target=f.target,
                    severity=Severity.CRITICAL,
                    description=f"Honeypot detected: '{r['pattern']}' matched {r['matches']}x",
                    evidence=r["context"][:500],
                ))

            elif rtype == "trigger_condition":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="honeypot_trigger",
                    target=f.target,
                    severity=Severity.CRITICAL,
                    description=f"Trigger conditions: {', '.join(r['keywords'])}",
                    evidence=(
                        f"Keywords: {', '.join(r['keywords'])}\n"
                        f"These PJL commands trigger credential delivery from the honeypot"
                    ),
                ))

            elif rtype == "socket_paths":
                for sp in r.get("paths", []):
                    analysis_findings.append(Finding(
                        phase="honeypot_analyzer",
                        type="pjl_socket_path",
                        target=f.target,
                        severity=Severity.HIGH,
                        description=f"Unix socket discovered: {sp}",
                        evidence=f"Socket path extracted from daemon source: {sp}",
                    ))

            elif rtype == "credential_flow":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="honeypot_credential_flow",
                    target=f.target,
                    severity=Severity.CRITICAL,
                    description="Credential delivery flow identified in daemon source",
                    evidence=r["context"][:500],
                ))

            elif rtype == "scm_rights":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="honeypot_scm_rights",
                    target=f.target,
                    severity=Severity.CRITICAL,
                    description="SCM_RIGHTS used for fd-passing credential delivery",
                    evidence="Daemon sends admin credentials via Unix socket SCM_RIGHTS\n"
                             "Requires: client connects to daemon socket after triggering PJL probes",
                ))

            elif rtype == "service_restart":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="service_auto_restart",
                    target=f.target,
                    severity=Severity.HIGH,
                    description="Service has auto-restart on failure — supports service hijack",
                    evidence="Restart=on-failure or Restart=always detected in service config",
                ))

            elif rtype == "interesting_functions":
                analysis_findings.append(Finding(
                    phase="honeypot_analyzer",
                    type="honeypot_function_discovery",
                    target=f.target,
                    severity=Severity.MEDIUM,
                    description=f"Interesting functions: {', '.join(r['functions'][:10])}",
                    evidence=r["context"][:500],
                ))

    return analysis_findings


async def run_honeypot_analyzer(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    logger.info(f"  [Honeypot Analyzer] Analyzing target {target}")

    # Phase 1: Analyze any source code retrieved in previous phases
    analysis_findings = await analyze_remote_service(target, all_findings)
    all_findings.extend(analysis_findings)

    # Phase 2: Generate exploitation strategy from analysis
    has_honeypot = any(f.type == "honeypot_confirmed" for f in analysis_findings)
    has_trigger = any(f.type == "honeypot_trigger" for f in analysis_findings)
    has_scm = any(f.type == "honeypot_scm_rights" for f in analysis_findings)
    has_socket = any(f.type == "pjl_socket_path" for f in analysis_findings)

    if has_honeypot and has_trigger and has_scm:
        strategy = (
            "EXPLOITATION STRATEGY:\n"
            "1. Send PJL FSUPLOAD/FSDOWNLOAD/FSQUERY commands to trigger honeypot\n"
            "2. Connect to daemon Unix socket to receive SCM_RIGHTS credentials\n"
            "3. Use received admin password for su privilege escalation\n"
            "4. Capture root flag\n\n"
            "REQUIRED TOOLS:\n"
            "- PJL module for sending trigger commands (port 9100 localhost only)\n"
            "- Relay chain if PJL not externally accessible\n"
            "- Socket SCM client for credential interception"
        )
        all_findings.append(Finding(
            phase="honeypot_analyzer",
            type="exploitation_strategy",
            target=target,
            severity=Severity.CRITICAL,
            description="Complete exploitation strategy generated from daemon source analysis",
            evidence=strategy,
        ))

    elif has_honeypot and has_trigger:
        strategy = (
            "PARTIAL STRATEGY:\n"
            "- Honeypot detected with trigger conditions\n"
            "- Socket or SCM_RIGHTS not confirmed in source\n"
            "- Recommend: retrieve full daemon binary for reverse engineering"
        )
        all_findings.append(Finding(
            phase="honeypot_analyzer",
            type="exploitation_strategy_partial",
            target=target,
            severity=Severity.HIGH,
            description="Partial exploitation strategy — missing socket details",
            evidence=strategy,
        ))

    # Phase 3: Generate summary of all analysis results
    if not analysis_findings:
        all_findings.append(Finding(
            phase="honeypot_analyzer",
            type="analysis_no_source",
            target=target,
            severity=Severity.INFO,
            description="No source code available for analysis",
            evidence="Source retrieval via PJL path traversal required before analysis",
        ))
        errors.append("No daemon source code available for analysis")

    latency = time.time() - t0
    new_findings = [f for f in all_findings if f.phase == "honeypot_analyzer"]

    return PhaseResult(
        phase="honeypot_analyzer",
        success=len(new_findings) > 0,
        findings=all_findings,
        summary=f"Honeypot analysis: {len(new_findings)} findings" +
                (f", strategy: {'complete' if has_honeypot and has_scm else 'partial'}" if new_findings else ""),
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
