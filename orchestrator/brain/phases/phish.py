import asyncio
import time
import logging
import os

from orchestrator.brain.phases.models import PhaseResult, Finding
from orchestrator.phishing.pipeline import PhishingPipeline

logger = logging.getLogger("phase_phish")


async def run_phish(target: str, findings: list = None) -> PhaseResult:
    t0 = time.time()
    errors = []

    pipeline = PhishingPipeline()

    target_email = os.getenv("PHISH_TARGET_EMAIL")
    phishing_domain = os.getenv("PHISH_DOMAIN")
    smtp_server = os.getenv("EXFIL_SMTP_SERVER")
    lhost = os.getenv("PHISH_LHOST", target)
    lport = int(os.getenv("PHISH_LPORT", "443"))

    if not target_email:
        return PhaseResult(
            phase="phish",
            success=False,
            summary="No target email configured (set PHISH_TARGET_EMAIL)",
            raw_output="phish skipped: PHISH_TARGET_EMAIL not set",
            latency=time.time() - t0,
            error="Missing PHISH_TARGET_EMAIL env var",
        )

    methods = []
    results = {}

    if os.getenv("GOPHISH_API_KEY"):
        methods.append("gophish")
    if phishing_domain:
        methods.append("evilginx")
    methods.append("set")

    for method in methods:
        try:
            result = await asyncio.to_thread(
                pipeline.run,
                method=method,
                target_email=target_email,
                target_url=f"http://{target}",
                phishing_domain=phishing_domain,
                smtp_server=smtp_server,
                lhost=lhost,
                lport=lport,
                use_skills=True,
                use_sandbox=False,
            )
            results[method] = result
        except Exception as e:
            logger.warning(f"Phish method {method} failed: {e}")
            errors.append(f"{method}:{e}")

    success = any(
        r.get("summary", {}).get("gophish_available") or
        r.get("summary", {}).get("evilginx_available") or
        r.get("components", {}).get("skill_phishing")
        for r in results.values()
    )

    latency = time.time() - t0
    return PhaseResult(
        phase="phish",
        success=success,
        summary=f"Phish: {len(methods)} methods attempted against {target_email}",
        raw_output=str(results) if results else "No phishing methods available",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )
