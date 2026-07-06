"""
Code Completeness Verifier — validates worm/pipeline output before acceptance.

Checks:
  1. Syntax validity (Python)
  2. Import existence (checks against known stdlib/common packages)
  3. Endpoint realism (queries RAG knowledge base to verify endpoint paths)
  4. Structural completeness (has functions, not just comments)

Usage:
  from orchestrator.code_verifier import verify_code
  result = verify_code("import os; os.system('id')", phase="exploit")
"""

import ast, re
from typing import List
from orchestrator.rag_knowledge import list_all_endpoints

STDLIB_MODULES = {
    "os", "sys", "re", "json", "base64", "hashlib", "hmac", "time",
    "datetime", "math", "random", "subprocess", "socket", "ssl",
    "http", "urllib", "xml", "csv", "io", "pathlib", "shutil",
    "tempfile", "itertools", "collections", "functools", "typing",
}

COMMON_THIRD_PARTY = {
    "requests", "flask", "django", "sqlalchemy", "numpy", "pandas",
    "scrapy", "beautifulsoup4", "bs4", "lxml", "cryptography", "jwt",
    "pyjwt", "paramiko", "scapy", "impacket", "pwntools", "pwn",
}

WINDOWS_INTERNALS = {
    "ctypes", "win32api", "win32security", "win32evtlog", "win32com",
    "pywin32", "ntsecurity", "psutil", "pymem", "pydbg", "capstone",
    "keystone", "unicorn",
}

ALLOWED_PACKAGES = STDLIB_MODULES | COMMON_THIRD_PARTY | WINDOWS_INTERNALS


def _check_syntax(code: str) -> dict:
    """Check Python syntax validity."""
    if not code or len(code.strip()) < 10:
        return {"valid": False, "error": "Empty or too short"}
    try:
        ast.parse(code)
        return {"valid": True, "error": ""}
    except SyntaxError as e:
        return {"valid": False, "error": f"SyntaxError: {e}"}


def _extract_imports(code: str) -> List[str]:
    """Extract all module names from import statements."""
    imports = []
    for line in code.split("\n"):
        line = line.strip()
        m = re.match(r"^import\s+(.+)", line)
        if m:
            for mod in m.group(1).split(","):
                mod = mod.strip().split(".")[0].split(" as ")[0].strip()
                if mod:
                    imports.append(mod)
        m = re.match(r"^from\s+(\S+)\s+import", line)
        if m:
            mod = m.group(1).split(".")[0].strip()
            if mod:
                imports.append(mod)
    return imports


def _check_imports(code: str) -> dict:
    """Check that imports reference known packages."""
    imports = _extract_imports(code)
    if not imports:
        return {"valid": True, "unrecognized": [], "note": "No imports found"}
    unrecognized = [i for i in imports if i not in ALLOWED_PACKAGES]
    if unrecognized:
        return {"valid": False, "unrecognized": unrecognized, "note": f"Unrecognized imports: {unrecognized}"}
    return {"valid": True, "unrecognized": [], "note": "All imports recognized"}


def _check_endpoints(code: str) -> dict:
    """Check if code references non-existent endpoints."""
    known = list_all_endpoints()
    known_urls = set(e["url"] for e in known)

    # Extract URL-like patterns from the code
    urls = set()
    for m in re.finditer(r'["\'](https?://[^"\']+)["\']', code):
        urls.add(m.group(1))
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_/{}<>-]+)["\']', code):
        candidate = m.group(1)
        # Check if it's a known endpoint or one of its variants
        urls.add(candidate)

    url_params = set()
    for u in urls:
        path = u.split("://")[-1] if "://" in u else u
        # Strip host:port
        if "/" in path:
            path = "/" + path.split("/", 1)[1] if "://" in u else path
        else:
            continue
        url_params.add(path)

    unknown = []
    for up in url_params:
        if up.startswith("/"):
            matched = False
            for k in known_urls:
                if _url_matches(up, k):
                    matched = True
                    break
            if not matched:
                unknown.append(up)

    if unknown:
        return {"valid": False, "unknown_endpoints": unknown, "note": f"Unknown endpoints: {unknown}"}
    return {"valid": True, "unknown_endpoints": [], "note": "All endpoints recognized"}


def _url_matches(candidate: str, known: str) -> bool:
    """Check if a candidate URL matches a known route pattern (including <int:pid> etc)."""
    # Direct match
    if candidate == known:
        return True
    # Pattern match: replace Flask-style params with regex
    known_re = re.sub(r"<[^>]+>", r"[^/]+", known)
    return bool(re.match(f"^{known_re}$", candidate))


def _check_structure(code: str, phase: str = "") -> dict:
    """Check code has reasonable structure for the given phase."""
    issues = []
    has_function = bool(re.search(r"def\s+\w+\s*\(", code))
    has_class = bool(re.search(r"class\s+\w+", code))
    has_http_call = bool(re.search(r"(requests\.(get|post|put|delete|patch)|urllib)", code))
    has_shell = bool(re.search(r"(os\.system|subprocess|os\.popen)", code))

    if not has_function and not has_class:
        issues.append("No function or class definition — likely incomplete")

    if phase in ("exploit", "postex", "exfil") and not has_http_call and not has_shell:
        issues.append(f"No HTTP call or shell execution for {phase} phase")

    if len(code.strip().split("\n")) < 3:
        issues.append("Very short (<3 lines) — likely incomplete")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "has_function": has_function,
        "has_class": has_class,
        "has_http_call": has_http_call,
    }


def _check_waf_payloads(code: str, phase: str = "") -> dict:
    if phase not in ("exploit", "postex"):
        return {"valid": True, "note": "WAF check only applies to exploit/postex phases"}
    waf_patterns = [
        r"XMLType\(",
        r"JSON_TABLE",
        r"extractvalue\(",
        r"updatexml\(",
        r"\\u0130",
        r"\\u017F",
        r"&param=.*&param=",
    ]
    found = [p for p in waf_patterns if re.search(p, code, re.IGNORECASE)]
    if found:
        return {"valid": True, "waf_patterns": found, "note": f"WAF bypass patterns detected: {found}"}
    return {"valid": True, "waf_patterns": [], "note": "No WAF bypass patterns — may trigger WAF if behind one"}


def _check_forensic_cleanup(code: str, phase: str = "") -> dict:
    if phase != "cleanup":
        return {"valid": True, "note": "Forensics check only applies to cleanup phase"}
    cleanup_checks = {
        "centos": [r"journalctl\s+--rotate", r"truncate.*\/var\/log", r"rm\s+-f\s+\/var\/log"],
        "windows": [r"wevtutil\s+cl", r"del\s+.*\.log"],
        "tomcat": [r"rm\s+.*access_log", r"catalina\.out"],
        "oracle": [r"AUD\$", r"DBMS_AUDIT", r"flashback"],
        "mssql": [r"sp_cycle_errorlog", r"xp_cmdshell"],
    }
    found_platforms = []
    for platform, patterns in cleanup_checks.items():
        if any(re.search(p, code) for p in patterns):
            found_platforms.append(platform)
    if found_platforms:
        return {"valid": True, "platforms": found_platforms, "note": f"Cleanup commands for: {found_platforms}"}
    return {"valid": True, "platforms": [], "note": "No cleanup commands detected — phase may be non-cleanup"}


def _check_dkom_patterns(code: str, phase: str = "") -> dict:
    if phase not in ("exploit", "postex"):
        return {"valid": True, "note": "DKOM check only applies to exploit/postex phases"}
    dkom_patterns = [
        r"NtQuerySystemInformation",
        r"NtSetInformationProcess",
        r"EtwEventWrite",
        r"NtTraceEvent",
        r"NtCreateThreadEx",
        r"NtOpenProcess",
        r"NtSuspendProcess",
        r"NtResumeProcess",
    ]
    found = [p for p in dkom_patterns if re.search(p, code)]
    if found:
        return {"valid": True, "dkom_patterns": found, "note": f"DKOM/syscall patterns detected: {found}"}
    return {"valid": True, "dkom_patterns": [], "note": "No direct syscall patterns — may use higher-level APIs"}


# ============================================================
# V3: Stealth & WAF Evasion Scoring
# ============================================================

STEALTH_PATTERNS = {
    "timing_jitter": r"(time\.sleep|asyncio\.sleep|random\.(uniform|gauss|expovariate))",
    "user_agent_rotation": r"(User-Agent|user_agent|rotate_ua)",
    "proxy_aware": r"(proxy|socks5|tor|PROXY_URL)",
    "low_and_slow": r"(limit|delay|throttle|ratelimit|rate_limit)",
    "retry_on_fail": r"(retry|backoff|exponential_backoff)",
    "noise_reduction": r"(minimal|stealth|quiet|silent)",
}

WAF_EVASION_PATTERNS = {
    "oracle_xmltype": r"XMLType|XMLTYPE",
    "json_table": r"JSON_TABLE|JSON_OBJECT|JSON_ARRAY",
    "unicode_bypass": r"\\u0130|\\u017F|\\uXXXX|unicode_normalize",
    "hpp": r"&param=.*&param=",
    "comment_injection": r"/\*.*\*/|--\s|#\s",
    "case_variation": r"(?i)\b(SeLeCt|UnIoN|OrD|InSeRt|UpDaTe|DrOp)\b",
    "content_type_mutation": r"multipart/form-data|application/json.*\b(sql|select|union)",
    "encoding_bypass": r"(base64|hex|url_encode|double_url)",
}

def _score_stealth(code: str) -> dict:
    found = {}
    for name, pattern in STEALTH_PATTERNS.items():
        matches = re.findall(pattern, code, re.IGNORECASE)
        if matches:
            found[name] = len(matches)
    score = min(1.0, len(found) / len(STEALTH_PATTERNS))
    return {"score": round(score, 2), "patterns": found, "count": len(found)}

def _score_waf_evasion(code: str) -> dict:
    found = {}
    for name, pattern in WAF_EVASION_PATTERNS.items():
        matches = re.findall(pattern, code, re.IGNORECASE)
        if matches:
            found[name] = len(matches)
    score = min(1.0, len(found) / len(WAF_EVASION_PATTERNS))
    return {"score": round(score, 2), "patterns": found, "count": len(found)}


def verify_code(code: str, phase: str = "") -> dict:
    """Run all completeness checks on generated code.

    Returns:
        verdict: "pass" | "fail"
        score: 0.0-1.0 completeness
        checks: list of individual check results
        issues: consolidated list of issues
    """
    results = {}
    issues = []

    # 1. Syntax
    syntax = _check_syntax(code)
    results["syntax"] = syntax
    if not syntax["valid"]:
        issues.append(syntax["error"])

    # 2. Imports
    imports = _check_imports(code)
    results["imports"] = imports
    if not imports["valid"]:
        issues.append(imports["note"])

    # 3. Endpoints
    endpoints = _check_endpoints(code)
    results["endpoints"] = endpoints
    if not endpoints["valid"]:
        issues.append(endpoints["note"])

    # 4. WAF payloads
    waf = _check_waf_payloads(code, phase)
    results["waf"] = waf

    # 5. Forensic cleanup
    forensics = _check_forensic_cleanup(code, phase)
    results["forensics"] = forensics

    # 6. DKOM / Ghost-in-the-Machine patterns
    dkom = _check_dkom_patterns(code, phase)
    results["dkom"] = dkom

    # 7. Stealth scoring
    stealth = _score_stealth(code)
    results["stealth"] = stealth

    # 8. WAF evasion scoring
    waf_evasion = _score_waf_evasion(code)
    results["waf_evasion"] = waf_evasion

    # 9. Structure
    structure = _check_structure(code, phase)
    results["structure"] = structure
    if not structure["valid"]:
        issues.extend(structure["issues"])

    passed = sum(1 for r in results.values() if r.get("valid"))
    total = len(results)
    base_score = passed / total if total > 0 else 0.0

    # Bonus: add stealth + waf_evasion scores as weighted boost (max +0.2)
    stealth_bonus = results.get("stealth", {}).get("score", 0.0) * 0.1
    waf_bonus = results.get("waf_evasion", {}).get("score", 0.0) * 0.1
    score = min(1.0, base_score + stealth_bonus + waf_bonus)

    has_critical = any(
        r.get("valid") == False and "syntax" not in str(r) and "empty" not in str(r)
        for r in results.values()
    )
    has_syntax_fail = not results.get("syntax", {}).get("valid", True)
    has_unknown_endpoints = not results.get("endpoints", {}).get("valid", True)

    critical_issues = []
    if has_syntax_fail:
        critical_issues.append("Syntax error")
    if has_unknown_endpoints:
        critical_issues.append("Unknown endpoint references")

    verdict = "pass"
    if has_syntax_fail or has_unknown_endpoints:
        verdict = "fail"
    elif score < 0.5:
        verdict = "fail"
    elif score < 0.75:
        verdict = "partial"

    return {
        "verdict": verdict,
        "score": round(score, 2),
        "checks": results,
        "issues": issues,
        "critical_issues": critical_issues,
        "summary": f"[{verdict.upper()}] score={score:.2f}, critical={len(critical_issues)}, warnings={len(issues)}",
    }


if __name__ == "__main__":
    tests = [
        ("valid exploit", "exploit", 'import requests\ndef exploit(target):\n    r = requests.get(f"{target}/api/v3/health")\n    return r.text\n'),
        ("syntax error", "exploit", 'import requests\ndef exploit(target:\n    pass\n'),
        ("bad endpoint", "exploit", 'import requests\ndef exploit():\n    requests.get("http://target/api/v1/user/profile")\n'),
        ("empty", "exploit", ""),
        ("shell command", "exploit", 'import os\ndef pwn():\n    os.system("id")\n'),
    ]
    for name, phase, code in tests:
        r = verify_code(code, phase)
        print(f"[{r['verdict'].upper()}] {name}: {r['summary']}")
        for issue in r["issues"]:
            print(f"  ! {issue}")
        print()
