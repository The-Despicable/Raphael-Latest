import time

from orchestrator.brain.phases.models import PhaseResult


async def run_phish(target: str, findings: list = None) -> PhaseResult:
    t0 = time.time()
    return PhaseResult(
        phase="phish",
        success=False,
        summary="Phishing requires GoPhish deployment (see P1 upgrade)",
        raw_output="Not implemented — needs P1 Docker image fixes",
        latency=time.time() - t0,
    )
