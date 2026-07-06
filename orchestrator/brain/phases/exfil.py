import time

from .models import PhaseResult


async def run_exfil(target: str, findings: list = None) -> PhaseResult:
    t0 = time.time()
    return PhaseResult(
        phase="exfil",
        success=False,
        summary="Exfiltration requires agent deployment (see P6 upgrade)",
        raw_output="Not implemented — needs P6 agent implant",
        latency=time.time() - t0,
    )
