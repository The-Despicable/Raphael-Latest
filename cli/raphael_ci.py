#!/usr/bin/env python3
"""Raphael CI/CD CLI — headless engagement launcher for pipeline integration."""

import argparse, asyncio, json, os, sys, time
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

API_BASE = os.getenv("RAPHAEL_API", "http://localhost:3900")
API_KEY = os.getenv("RAPHAEL_API_KEY", "")


async def _request(method: str, path: str, body: dict = None) -> dict:
    import httpx
    headers = {"User-Agent": "raphael-ci/2.0"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    url = f"{API_BASE}{path}"
    async with httpx.AsyncClient(timeout=300) as client:
        if method == "GET":
            resp = await client.get(url, headers=headers)
        elif method == "POST":
            resp = await client.post(url, json=body or {}, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        if not resp.is_success:
            sys.stderr.write(f"Error {resp.status_code}: {resp.text}\n")
            return {}
        return resp.json()


def _print(data: dict, raw: bool = False):
    if raw:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(json.dumps(data, default=str))


async def cmd_health(args):
    data = await _request("GET", "/v1/ci/health")
    _print(data, args.raw)


async def cmd_engage_run(args):
    body = {
        "target": args.target,
        "phases": args.phases.split(",") if args.phases else None,
        "persona": args.persona,
        "no_proxy": args.no_proxy,
        "webhook_url": args.webhook,
    }
    resp = await _request("POST", "/v1/ci/engage", body)
    eng_id = resp.get("id", "")
    if not eng_id:
        sys.exit(1)
    print(f"Engagement {eng_id} queued — waiting for completion...")

    while True:
        await asyncio.sleep(5)
        status = await _request("GET", f"/v1/ci/engage/{eng_id}")
        s = status.get("status", "")
        print(f"  Status: {s}", end="\r")
        if s in ("complete", "failed"):
            print()
            break

    report = await _request("GET", f"/v1/ci/report/{eng_id}")
    _print(report, args.raw)


async def cmd_engage_start(args):
    body = {
        "target": args.target,
        "phases": args.phases.split(",") if args.phases else None,
        "persona": args.persona,
        "no_proxy": args.no_proxy,
        "webhook_url": args.webhook,
    }
    resp = await _request("POST", "/v1/ci/engage", body)
    eng_id = resp.get("id", "")
    if eng_id:
        print(eng_id)
    else:
        sys.exit(1)


async def cmd_engage_status(args):
    data = await _request("GET", f"/v1/ci/engage/{args.id}")
    _print(data, args.raw)


async def cmd_report(args):
    data = await _request("GET", f"/v1/ci/report/{args.id}?format={args.format}")
    _print(data, args.raw)


async def cmd_scan(args):
    body = {
        "target": args.target,
        "persona": args.persona,
        "no_proxy": args.no_proxy,
    }
    data = await _request("POST", "/v1/ci/scan", body)
    _print(data, args.raw)


def main():
    parser = argparse.ArgumentParser(
        prog="raphael-ci",
        description="Raphael CI/CD integration tool — headless pentesting for pipelines.",
    )
    parser.add_argument("--raw", action="store_true", help="Print raw JSON output")
    sub = parser.add_subparsers(dest="command")

    p_health = sub.add_parser("health", help="Check API health")

    p_engage = sub.add_parser("engage", help="Manage engagements")
    engage_sub = p_engage.add_subparsers(dest="action")

    p_run = engage_sub.add_parser("run", help="Run engagement (blocking)")
    p_run.add_argument("target")
    p_run.add_argument("--phases", default=None, help="Comma-separated phase list")
    p_run.add_argument("--persona", default=None, help="Persona override (e.g. blackhat)")
    p_run.add_argument("--no-proxy", action="store_true", help="Skip Tor proxy")
    p_run.add_argument("--webhook", default=None, help="Webhook URL for async notification")

    p_start = engage_sub.add_parser("start", help="Start engagement (non-blocking, returns ID)")
    p_start.add_argument("target")
    p_start.add_argument("--phases", default=None, help="Comma-separated phase list")
    p_start.add_argument("--persona", default=None, help="Persona override (e.g. blackhat)")
    p_start.add_argument("--no-proxy", action="store_true", help="Skip Tor proxy")
    p_start.add_argument("--webhook", default=None, help="Webhook URL for async notification")

    p_status = engage_sub.add_parser("status", help="Check engagement status")
    p_status.add_argument("id")

    p_report = sub.add_parser("report", help="Get structured report")
    p_report.add_argument("id")
    p_report.add_argument("--format", default="json", choices=["json", "sarif", "junit"])

    p_scan = sub.add_parser("scan", help="Quick synchronous recon+scan")
    p_scan.add_argument("target")
    p_scan.add_argument("--persona", default=None)
    p_scan.add_argument("--no-proxy", action="store_true")

    args = parser.parse_args()

    if args.command == "health":
        asyncio.run(cmd_health(args))
    elif args.command == "engage":
        if args.action == "run":
            asyncio.run(cmd_engage_run(args))
        elif args.action == "start":
            asyncio.run(cmd_engage_start(args))
        elif args.action == "status":
            asyncio.run(cmd_engage_status(args))
        else:
            parser.print_help()
    elif args.command == "report":
        asyncio.run(cmd_report(args))
    elif args.command == "scan":
        asyncio.run(cmd_scan(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
