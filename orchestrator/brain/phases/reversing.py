import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_reversing")

SUSPICIOUS_PATTERNS = {
    "shell_exec": [
        r"system\s*\(", r"popen\s*\(", r"execv\s*\(", r"execl\s*\(",
        r"shell\s*\(", r"subprocess\.", r"os\.system", r"os\.popen",
    ],
    "command_injection": [
        r"shell\s*=\s*True", r"format.*\{.*\}", r"%\s*[\"']",
        r"f[\"'].*\{.*\}.*[\"']", r"eval\s*\(", r"exec\s*\(",
    ],
    "network": [
        r"socket\s*\(", r"connect\s*\(", r"bind\s*\(", r"listen\s*\(",
        r"accept\s*\(", r"recv\s*\(", r"send\s*\(",
    ],
    "file_ops": [
        r"fopen\s*\(", r"open\s*\(", r"read\s*\(", r"write\s*\(",
        r"mmap\s*\(", r"unlink\s*\(", r"remove\s*\(",
    ],
    "crypto": [
        r"AES", r"RSA", r"DES", r"MD5", r"SHA1", r"SHA256",
        r"encrypt", r"decrypt", r"cipher",
    ],
    "anti_debug": [
        r"ptrace", r"is_debugger_present", r"CheckRemoteDebuggerPresent",
        r"NtQueryInformationProcess", r"TlsGetValue", r"TrapFlag",
    ],
    "persistence": [
        r"RunKey", r"Startup", r"ScheduledTask", r"cron",
        r"service.*install", r"daemon", r"systemd",
    ],
}

DANGEROUS_FUNCTIONS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf",
    "fscanf", "sscanf", "realpath", "getwd", "wget", "curl",
    "system", "popen", "exec", "shell", "eval",
}


def _run_r2pipe_analysis(binary_path: str) -> dict:
    try:
        import r2pipe
    except ImportError:
        return {"error": "r2pipe not installed"}

    try:
        r2 = r2pipe.open(binary_path, flags=["-2"])
        r2.cmd("aaa")

        info = json.loads(r2.cmd("ij"))
        strings = r2.cmd("izj")
        imports = r2.cmd("iij")
        sections = r2.cmd("iSj")
        symbols = r2.cmd("isj")
        entry = r2.cmd("iej")
        functions = r2.cmd("aflj")

        r2.quit()

        return {
            "info": info,
            "strings": json.loads(strings) if strings else [],
            "imports": json.loads(imports) if imports else [],
            "sections": json.loads(sections) if sections else [],
            "symbols": json.loads(symbols) if symbols else [],
            "entry": json.loads(entry) if entry else {},
            "functions": json.loads(functions) if functions else [],
        }
    except Exception as e:
        logger.warning(f"r2pipe analysis failed: {e}")
        return {"error": str(e)}


def _run_strings(binary_path: str) -> list[str]:
    try:
        result = subprocess.run(
            ["strings", "-n", "4", binary_path],
            capture_output=True, text=True, timeout=30
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _analyze_strings(strings: list[str]) -> dict:
    findings = {
        "ips": [],
        "urls": [],
        "paths": [],
        "creds": [],
        "crypto": [],
        "suspicious": [],
    }

    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    path_re = re.compile(r"(?:/[a-zA-Z0-9._-]+){2,}")
    cred_re = re.compile(r"(?:password|passwd|pwd|secret|key|token|api_key)\s*[:=]\s*\S+", re.I)

    for s in strings:
        if ip_re.search(s):
            findings["ips"].extend(ip_re.findall(s))
        if url_re.search(s):
            findings["urls"].extend(url_re.findall(s))
        if path_re.search(s):
            findings["paths"].extend(path_re.findall(s))
        if cred_re.search(s):
            findings["creds"].append(s[:200])

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for s in strings:
            for pat in patterns:
                if re.search(pat, s, re.I):
                    findings["suspicious"].append({"category": category, "string": s[:200]})
                    break

    return findings


def _analyze_imports(imports: list[dict]) -> dict:
    dangerous = []
    network = []
    crypto = []
    all_imports = []

    for imp in imports:
        name = imp.get("name", "").lower()
        all_imports.append(name)

        if name in DANGEROUS_FUNCTIONS:
            dangerous.append(name)
        if any(kw in name for kw in ["socket", "connect", "bind", "listen", "accept", "http", "curl", "wget"]):
            network.append(name)
        if any(kw in name for kw in ["aes", "rsa", "des", "md5", "sha", "crypto", "cipher", "encrypt", "decrypt"]):
            crypto.append(name)

    return {
        "dangerous": list(set(dangerous)),
        "network": list(set(network)),
        "crypto": list(set(crypto)),
        "total": len(all_imports),
        "unique": len(set(all_imports)),
    }


def _analyze_functions(functions: list[dict], imports: list[dict]) -> dict:
    large_funcs = []
    complex_funcs = []
    recursive = []
    calls_dangerous = []

    import_names = {imp.get("name", "").lower() for imp in imports}

    for func in functions:
        size = func.get("size", 0)
        if size > 500:
            large_funcs.append({"name": func.get("name"), "size": size})

        cc = func.get("cyclomatic_complexity", 0)
        if cc > 20:
            complex_funcs.append({"name": func.get("name"), "cc": cc})

        if func.get("name") in func.get("callrefs", []):
            recursive.append(func.get("name"))

        for call in func.get("callrefs", []):
            if call.get("name", "").lower() in DANGEROUS_FUNCTIONS:
                calls_dangerous.append({"func": func.get("name"), "calls": call.get("name")})

    return {
        "large_functions": large_funcs[:10],
        "complex_functions": complex_funcs[:10],
        "recursive": recursive[:5],
        "calls_dangerous": calls_dangerous[:10],
        "total_functions": len(functions),
    }


async def run_reversing(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    binaries = _collect_binaries(findings)

    for bin_info in binaries:
        try:
            result = await _analyze_binary(bin_info)
            all_findings.extend(result)
        except Exception as e:
            logger.warning(f"Binary analysis failed for {bin_info}: {e}")
            errors.append(f"{bin_info}: {e}")

    latency = time.time() - t0
    return PhaseResult(
        phase="reversing",
        success=len(all_findings) > len(findings or []),
        findings=all_findings,
        summary=f"Reversing: analyzed {len(binaries)} binaries, {len(all_findings) - len(findings or [])} new findings",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _collect_binaries(findings: list[Finding] = None) -> list[dict]:
    binaries = []

    for f in findings or []:
        if f.type == "binary_found" and f.evidence:
            binaries.append({
                "path": f.evidence,
                "source": "web_download",
                "target": f.target,
            })
        if f.type == "downloaded_binary" and f.payload:
            try:
                data = json.loads(f.payload) if isinstance(f.payload, str) else f.payload
                if "path" in data:
                    binaries.append({
                        "path": data["path"],
                        "source": "web_download",
                        "target": f.target,
                    })
            except Exception:
                logger.debug("Non-critical error", exc_info=True)

    return binaries


async def _analyze_binary(bin_info: dict) -> list[Finding]:
    path = bin_info["path"]
    target = bin_info.get("target", "unknown")

    if not os.path.exists(path):
        return [Finding(
            phase="reversing", type="binary_missing", target=target,
            severity=Severity.LOW,
            description=f"Binary not found: {path}",
        )]

    r2_result = await asyncio.get_event_loop().run_in_executor(None, _run_r2pipe_analysis, path)
    strings = await asyncio.get_event_loop().run_in_executor(None, _run_strings, path)

    findings = []

    if "error" not in r2_result:
        info = r2_result.get("info", {})
        arch = info.get("arch", "unknown")
        bits = info.get("bits", 0)
        os_type = info.get("os", "unknown")
        endian = info.get("endian", "unknown")

        findings.append(Finding(
            phase="reversing", type="binary_info", target=target,
            severity=Severity.INFO,
            description=f"Binary: {arch}/{bits}-bit {os_type} {endian}",
            evidence=f"{path} ({info.get('size', 0)} bytes)",
            raw={"arch": arch, "bits": bits, "os": os_type, "endian": endian},
        ))

        strings_analysis = _analyze_strings(strings)
        if strings_analysis["ips"]:
            findings.append(Finding(
                phase="reversing", type="embedded_ips", target=target,
                severity=Severity.MEDIUM,
                description=f"Embedded IPs in binary: {', '.join(strings_analysis['ips'][:5])}",
                evidence="; ".join(strings_analysis["ips"][:10]),
            ))
        if strings_analysis["urls"]:
            findings.append(Finding(
                phase="reversing", type="embedded_urls", target=target,
                severity=Severity.MEDIUM,
                description=f"Embedded URLs in binary: {', '.join(strings_analysis['urls'][:5])}",
                evidence="; ".join(strings_analysis["urls"][:10]),
            ))
        if strings_analysis["creds"]:
            findings.append(Finding(
                phase="reversing", type="embedded_creds", target=target,
                severity=Severity.HIGH,
                description="Possible credentials/keys embedded in binary",
                evidence="; ".join(strings_analysis["creds"][:3]),
            ))
        for s in strings_analysis["suspicious"][:5]:
            findings.append(Finding(
                phase="reversing", type="suspicious_string", target=target,
                severity=Severity.MEDIUM,
                description=f"Suspicious string ({s['category']}): {s['string'][:100]}",
                evidence=s["string"],
            ))

        imports = r2_result.get("imports", [])
        if imports:
            import_analysis = _analyze_imports(imports)
            if import_analysis["dangerous"]:
                findings.append(Finding(
                    phase="reversing", type="dangerous_imports", target=target,
                    severity=Severity.HIGH,
                    description=f"Dangerous imports: {', '.join(import_analysis['dangerous'][:5])}",
                    evidence="; ".join(import_analysis["dangerous"]),
                ))
            if import_analysis["network"]:
                findings.append(Finding(
                    phase="reversing", type="network_imports", target=target,
                    severity=Severity.MEDIUM,
                    description=f"Network-related imports: {', '.join(import_analysis['network'][:5])}",
                    evidence="; ".join(import_analysis["network"]),
                ))

        functions = r2_result.get("functions", [])
        if functions:
            func_analysis = _analyze_functions(functions, imports)
            if func_analysis["calls_dangerous"]:
                findings.append(Finding(
                    phase="reversing", type="calls_dangerous_funcs", target=target,
                    severity=Severity.HIGH,
                    description=f"Functions calling dangerous APIs: {len(func_analysis['calls_dangerous'])}",
                    evidence="; ".join([f"{c['func']}->{c['calls']}" for c in func_analysis["calls_dangerous"][:5]]),
                ))

    else:
        strings_analysis = _analyze_strings(strings)
        if strings_analysis["ips"] or strings_analysis["urls"] or strings_analysis["creds"]:
            findings.append(Finding(
                phase="reversing", type="strings_analysis", target=target,
                severity=Severity.MEDIUM,
                description="Strings analysis (r2 unavailable)",
                evidence=f"IPs: {len(strings_analysis['ips'])}, URLs: {len(strings_analysis['urls'])}, Creds: {len(strings_analysis['creds'])}",
            ))

    return findings


async def run_binary_analysis(target: str, findings: list[Finding] = None) -> PhaseResult:
    return await run_reversing(target, findings)