import asyncio
import logging
import os
import re
import time
from typing import Optional

import requests

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_web_scan")

WEB_ROOTS = ["", "/admin", "/api", "/login", "/wp-admin", "/administrator",
             "/backend", "/panel", "/dashboard", "/cms", "/manager",
             "/console", "/phpmyadmin", "/api/v1", "/api/v2", "/graphql",
             "/swagger", "/docs", "/uploads", "/files", "/assets",
             "/backup", "/config", "/setup", "/install", "/.git",
             "/.env", "/robots.txt", "/sitemap.xml", "/crossdomain.xml"]

LOGIN_PATTERNS = [
    re.compile(r'<input[^>]*type=["\']password["\']', re.I),
    re.compile(r'login|sign[_-]?in|log[_-]?in', re.I),
    re.compile(r'<form[^>]*action=["\'][^"\']*login', re.I),
]

FORM_PATTERNS = [
    re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.I),
    re.compile(r'<input[^>]*type=["\'](?:text|email|password|file)["\']', re.I),
]


async def run_web_scan(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []
    loop = asyncio.get_running_loop()

    http_ports = set()
    for f in all_findings:
        if f.port and f.port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000):
            http_ports.add(f.port)
        if f.service in ("http", "https", "http-proxy", "http-alt", "https-alt"):
            http_ports.add(f.port or 80)

    if not http_ports:
        http_ports.add(80)

    for port in sorted(http_ports):
        scheme = "https" if port in (443, 8443, 4443) else "http"
        base_url = f"{scheme}://{target}:{port}"

        vhosts = [target]
        try:
            hosts_path = os.getenv("HOSTS_FILE", "/etc/hosts")
            with open(hosts_path) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == target:
                            vhosts.extend(parts[1:])
        except Exception:
            logger.debug("Non-critical error", exc_info=True)

        for vhost in set(vhosts):
            logger.info(f"  [WebScan] Probing {base_url} (Host: {vhost})")
            url = base_url

            try:
                resp = await loop.run_in_executor(None, lambda: requests.get(
                    url, headers={"Host": vhost, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"},
                    timeout=8, verify=False, allow_redirects=True,
                ))
                all_findings.append(Finding(
                    phase="web_scan", type="http_response", target=target,
                    host=vhost, port=port, severity=Severity.INFO,
                    description=f"HTTP {resp.status_code} on {url} ({len(resp.content)} bytes)",
                    evidence=f"Title: {_extract_title(resp.text)[:100]} | Server: {resp.headers.get('Server', '?')}",
                    raw={"status": resp.status_code, "headers": dict(resp.headers), "body_preview": resp.text[:500]},
                ))

                for path in WEB_ROOTS:
                    try:
                        pu = f"{url}{path}"
                        pr = await loop.run_in_executor(None, lambda u=pu: requests.get(
                            u, headers={"Host": vhost}, timeout=5, verify=False, allow_redirects=False,
                        ))
                        sev = Severity.HIGH if pr.status_code == 200 and path in (
                            "/.git", "/.env", "/backup", "/config") else Severity.INFO
                        if pr.status_code not in (404,):
                            all_findings.append(Finding(
                                phase="web_scan", type="web_path", target=target,
                                host=vhost, port=port, severity=sev,
                                description=f"{path} → HTTP {pr.status_code}",
                                evidence=f"{pu} ({len(pr.content)} bytes)",
                            ))
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)

                html = resp.text

                login_forms = []
                for lp in LOGIN_PATTERNS:
                    if lp.search(html):
                        login_forms.append(lp.pattern[:40])
                if login_forms:
                    all_findings.append(Finding(
                        phase="web_scan", type="login_form", target=target,
                        host=vhost, port=port, severity=Severity.MEDIUM,
                        description=f"Login form detected on {url}",
                        evidence="; ".join(login_forms[:3]),
                    ))

                forms_found = []
                for fp in FORM_PATTERNS:
                    for m in fp.finditer(html):
                        forms_found.append(m.group(1) if m.groups() else m.group(0))
                if forms_found:
                    all_findings.append(Finding(
                        phase="web_scan", type="html_form", target=target,
                        host=vhost, port=port, severity=Severity.INFO,
                        description=f"{len(forms_found)} form(s) on {url}",
                        evidence="; ".join(forms_found[:5]),
                    ))

                auth_headers = [h for h in resp.headers if h.lower()
                                in ("www-authenticate", "authorization")]
                if auth_headers:
                    all_findings.append(Finding(
                        phase="web_scan", type="http_auth", target=target,
                        host=vhost, port=port, severity=Severity.MEDIUM,
                        description=f"HTTP auth required: {', '.join(auth_headers)}",
                        evidence=resp.headers.get("WWW-Authenticate", ""),
                    ))

            except requests.ConnectionError:
                all_findings.append(Finding(
                    phase="web_scan", type="connection_error", target=target,
                    host=vhost, port=port, severity=Severity.INFO,
                    description=f"Could not connect to {url}",
                ))
            except Exception as e:
                logger.warning(f"  [WebScan] {url} error: {e}")
                errors.append(f"{url}:{e}")

    latency = time.time() - t0
    new_findings = [f for f in all_findings if f.phase == "web_scan"]
    path_count = sum(1 for f in new_findings if f.type == "web_path")
    login_count = sum(1 for f in new_findings if f.type == "login_form")

    return PhaseResult(
        phase="web_scan",
        success=len(new_findings) > 0,
        findings=all_findings,
        summary=f"Web scan: {len(new_findings)} findings ({path_count} paths, {login_count} login forms)",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _extract_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""
