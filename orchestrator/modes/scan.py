import json, sys
from ..scanners.pipeline import ScanPipeline
from ..proxy_guard import ProxyGuard, ProxyError


async def handle(target: str, ports: str = "1-1000",
                 nuclei_severity: str = None,
                 use_proxy: bool = True) -> dict:
    pg = None
    if use_proxy:
        try:
            pg = ProxyGuard()
            pg.verify()
        except ProxyError as e:
            return {"error": f"Proxy verification failed: {e}",
                    "target": target, "note": "Run with use_proxy=False to skip proxy"}
    else:
        print("[scan] WARNING: Scanning without proxy. This will expose your real IP.")

    pipeline = ScanPipeline(pg)
    results = await pipeline.run(target, ports=ports, nuclei_severity=nuclei_severity)

    if pg:
        pg.abort()

    return results


if __name__ == "__main__":
    import asyncio

    if len(sys.argv) < 2:
        print("Usage: python -m orchestrator.modes.scan <target> [--ports N-M] [--nuclei-severity critical|high|medium|low] [--no-proxy]")
        sys.exit(1)

    target = sys.argv[1]
    ports = "1-1000"
    sev = None
    proxy = True

    args = sys.argv[2:]
    for i, a in enumerate(args):
        if a == "--ports" and i + 1 < len(args):
            ports = args[i + 1]
        elif a == "--nuclei-severity" and i + 1 < len(args):
            sev = args[i + 1]
        elif a == "--no-proxy":
            proxy = False

    result = asyncio.run(handle(target, ports=ports, nuclei_severity=sev, use_proxy=proxy))
    print(json.dumps(result, indent=2))
