#!/usr/bin/env python3
"""Raphael Health Check — verify all Docker containers, tools, and API endpoints.

Usage:
  python -m cli.health_check [--host 127.0.0.1] [--docker] [--all]
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

SERVICES = {
    "cai-service":      {"port": 3201, "path": "/agent/recon",    "method": "POST", "label": "AI Orchestration"},
    "mhddos-service":   {"port": 3301, "path": "/",               "method": "GET",  "label": "DDoS Engine"},
    "cloak-service":    {"port": 3401, "path": "/",               "method": "GET",  "label": "Traffic Cloaking"},
    "orchestrator-api": {"port": 3501, "path": "/health",         "method": "GET",  "label": "Orchestrator API"},
    "c2-server":        {"port": 3505, "path": "/v1/agent/health","method": "GET",  "label": "C2 Server"},
    "phishing":         {"port": 3502, "path": "/health",         "method": "GET",  "label": "Phishing Engine"},
    "recon-pipeline":   {"port": 3503, "path": "/health",         "method": "GET",  "label": "Recon Pipeline"},
    "sword":            {"port": 3600, "path": "/health",         "method": "GET",  "label": "Sword Orchestrator"},
    "autonomous-brain": {"port": 3700, "path": "/health",         "method": "GET",  "label": "Autonomous Brain"},
    "kali-tools":       {"port": 3800, "path": "/health",         "method": "GET",  "label": "Kali Tools"},
    "raphael-api":      {"port": 3900, "path": "/v1/ci/health",   "method": "GET",  "label": "Raphael API"},
    "tor-proxy":        {"port": 9050, "path": None,              "method": "SOCKS","label": "Tor Proxy"},
    "sliver-server":    {"port": 31337,"path": None,              "method": "TCP",  "label": "Sliver C2"},
    "neo4j":            {"port": 7687, "path": None,              "method": "TCP",  "label": "Neo4j Database"},
    "caido":            {"port": 48080,"path": "/",               "method": "GET",  "label": "Caido Web Proxy"},
}

TOOLS = {
    "nmap":           {"label": "Nmap Port Scanner"},
    "netexec":        {"label": "NetExec (CrackMapExec)"},
    "nuclei":         {"label": "Nuclei Vulnerability Scanner"},
    "whatweb":        {"label": "WhatWeb Fingerprinter"},
    "hydra":          {"label": "Hydra Brute Forcer"},
    "sqlmap":         {"label": "SQLMap"},
    "john":           {"label": "John the Ripper"},
    "sshpass":        {"label": "SSH Pass (auto-deploy)"},
    "openssl":        {"label": "OpenSSL"},
    "python3":        {"label": "Python 3"},
    "docker":         {"label": "Docker CLI"},
    "docker-compose": {"label": "Docker Compose"},
}

DOCKER_CONTAINERS = [
    "raphael-cai-service", "raphael-mhddos-service", "raphael-cloak-service",
    "raphael-c2-server", "raphael-phishing", "raphael-recon-pipeline",
    "raphael-sword", "raphael-autonomous-brain", "raphael-tor-proxy",
    "raphael-sliver-server", "raphael-neo4j", "raphael-kali-tools",
    "raphael-raphael-api", "raphael-caido",
]

ENV_CHECKS = {
    "NVIDIA_API_KEY":   {"required": False, "min_len": 8,  "label": "NVIDIA API Key"},
    "OPENAI_API_KEY":   {"required": False, "min_len": 8,  "label": "OpenAI API Key"},
    "TOR_CONTROL_PASS": {"required": True,  "min_len": 16, "label": "Tor Control Password"},
    "API_KEY":          {"required": True,  "min_len": 32, "label": "API Gateway Key"},
    "GOPHISH_API_KEY":  {"required": False, "min_len": 32, "label": "Gophish API Key"},
    "NEO4J_PASS":       {"required": True,  "min_len": 16, "label": "Neo4j Password"},
    "SHODAN_API_KEY":   {"required": False, "min_len": 8,  "label": "Shodan API Key"},
}


class CheckResult:
    def __init__(self, name: str, label: str, status: str, detail: str = ""):
        self.name = name
        self.label = label
        self.status = status
        self.detail = detail

    def to_dict(self):
        return {"name": self.name, "label": self.label, "status": self.status, "detail": self.detail}


def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def check_http(host: str, port: int, path: str, method: str = "GET", timeout: float = 5.0) -> tuple:
    import httpx
    try:
        url = f"http://{host}:{port}{path}"
        async with httpx.AsyncClient(timeout=timeout) as client:
            if method == "GET":
                resp = await client.get(url)
            else:
                resp = await client.post(url, json={"target": "127.0.0.1"})
            if resp.status_code < 500:
                return True, f"HTTP {resp.status_code}"
            return False, f"HTTP {resp.status_code}"
    except httpx.RequestError as e:
        return False, str(e.__class__.__name__)
    except Exception as e:
        return False, str(e)[:60]


async def check_service(name: str, cfg: dict, host: str = "127.0.0.1") -> CheckResult:
    port = cfg["port"]
    path = cfg.get("path")
    method = cfg.get("method", "GET")
    label = cfg.get("label", name)

    if path:
        ok, detail = await check_http(host, port, path, method)
        if ok:
            return CheckResult(name, label, "PASS", detail)
        return CheckResult(name, label, "FAIL", detail)
    elif cfg.get("method") == "SOCKS":
        ok = check_tcp_port(host, port)
        if ok:
            return CheckResult(name, label, "PASS", "SOCKS port open")
        return CheckResult(name, label, "FAIL", "Connection refused")
    elif cfg.get("method") == "TCP":
        ok = check_tcp_port(host, port)
        if ok:
            return CheckResult(name, label, "PASS", "TCP port open")
        return CheckResult(name, label, "FAIL", "Connection refused")
    return CheckResult(name, label, "SKIP", "No check defined")


def check_binary(name: str, label: str) -> CheckResult:
    path = shutil.which(name)
    if path:
        return CheckResult(name, label, "PASS", path)
    return CheckResult(name, label, "WARN", "Not found in PATH")


def check_docker_container(name: str) -> CheckResult:
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        if name in result.stdout:
            return CheckResult(name, f"Container {name}", "PASS", "Running")
        result_all = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        if name in result_all.stdout:
            return CheckResult(name, f"Container {name}", "WARN", "Exists but stopped")
        return CheckResult(name, f"Container {name}", "FAIL", "Not found")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return CheckResult(name, f"Container {name}", "SKIP", "Docker unavailable")


def check_env_var(key: str, cfg: dict) -> CheckResult:
    val = os.getenv(key, "")
    label = cfg.get("label", key)
    if not val:
        if cfg.get("required"):
            return CheckResult(key, label, "FAIL", "Not set (required)")
        return CheckResult(key, label, "WARN", "Not set (optional)")
    if cfg.get("min_len") and len(val) < cfg["min_len"]:
        return CheckResult(key, label, "WARN", f"Only {len(val)} chars (min {cfg['min_len']})")
    return CheckResult(key, label, "PASS", f"{len(val)} chars")


def check_docker_engine() -> CheckResult:
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return CheckResult("docker-engine", "Docker Engine", "PASS", f"v{result.stdout.strip()}")
        return CheckResult("docker-engine", "Docker Engine", "FAIL", result.stderr.strip()[:60])
    except FileNotFoundError:
        return CheckResult("docker-engine", "Docker Engine", "FAIL", "Docker not installed")
    except subprocess.TimeoutExpired:
        return CheckResult("docker-engine", "Docker Engine", "FAIL", "Timeout")


def check_docker_compose_ver() -> CheckResult:
    try:
        result = subprocess.run(
            ["docker", "compose", "version", "--short"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return CheckResult("docker-compose", "Docker Compose", "PASS", f"v{result.stdout.strip()}")
        return CheckResult("docker-compose", "Docker Compose", "FAIL", result.stderr.strip()[:60])
    except FileNotFoundError:
        return CheckResult("docker-compose", "Docker Compose", "FAIL", "Not installed")


def check_env_file() -> CheckResult:
    for path in [".env", "../.env", os.path.join(os.path.dirname(__file__), "..", ".env")]:
        expanded = os.path.abspath(path)
        if os.path.exists(expanded):
            return CheckResult("env-file", ".env File", "PASS", expanded)
    return CheckResult("env-file", ".env File", "WARN", "Not found (copy .env.example to .env)")


async def run_all_checks(host: str = "127.0.0.1", check_docker: bool = False) -> dict:
    results = {"services": [], "tools": [], "docker": [], "env": [], "timestamp": datetime.utcnow().isoformat()}

    results["env"].append(check_env_file())
    for key, cfg in ENV_CHECKS.items():
        results["env"].append(check_env_var(key, cfg))

    results["docker"].append(check_docker_engine())
    results["docker"].append(check_docker_compose_ver())

    if check_docker:
        for name in DOCKER_CONTAINERS:
            results["docker"].append(check_docker_container(name))

    for name, cfg in SERVICES.items():
        results["services"].append(await check_service(name, cfg, host))

    for name, cfg in TOOLS.items():
        results["tools"].append(check_binary(name, cfg["label"]))

    return results


def print_results(results: dict):
    passed = warned = failed = 0

    for category, items in results.items():
        if category == "timestamp" or not items:
            continue

        fail_items = [r for r in items if r.status == "FAIL"]
        warn_items = [r for r in items if r.status == "WARN"]
        pass_items = [r for r in items if r.status == "PASS"]

        if fail_items:
            print(f"\n  {'-' * 54}")
            print(f"  FAILED — {category.upper()}")
            print(f"  {'-' * 54}")
            for r in fail_items:
                print(f"    X  {r.label:<40} [FAIL]  {r.detail}")

        if warn_items:
            print(f"\n  {'-' * 54}")
            print(f"  WARNINGS — {category.upper()}")
            print(f"  {'-' * 54}")
            for r in warn_items:
                print(f"    !  {r.label:<40} [WARN]  {r.detail}")

        if pass_items and not fail_items and not warn_items:
            print(f"\n  {category.upper()}: All {len(pass_items)} checks passed")

        passed += len(pass_items)
        warned += len(warn_items)
        failed += len(fail_items)

    total = passed + warned + failed
    print(f"\n  {'=' * 54}")
    print(f"  RESULTS:  {passed} PASSED  |  {warned} WARNINGS  |  {failed} FAILED  |  {total} TOTAL")
    print(f"  {'=' * 54}\n")

    if failed > 0:
        sys.exit(1)


async def main_async():
    host = "127.0.0.1"
    check_docker = "--docker" in sys.argv or "--all" in sys.argv
    if "--host" in sys.argv:
        idx = sys.argv.index("--host")
        if idx + 1 < len(sys.argv):
            host = sys.argv[idx + 1]

    print(f"\n  Raphael Health Check — Target: {host}")
    if check_docker:
        print(f"  Docker checks: enabled\n")
    else:
        print(f"  (use --docker or --all for container checks)\n")

    results = await run_all_checks(host=host, check_docker=check_docker)
    print_results(results)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
