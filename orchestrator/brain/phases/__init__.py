from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.brain.phases.recon import run_recon
from orchestrator.brain.phases.scan import run_scan
from orchestrator.brain.phases.exploit import run_exploit
from orchestrator.brain.phases.postex import run_postex
from orchestrator.brain.phases.lateral import run_lateral
from orchestrator.brain.phases.credential import run_credential
from orchestrator.brain.phases.exfil import run_exfil
from orchestrator.brain.phases.phish import run_phish

PHASE_EXECUTORS = {
    "recon": run_recon,
    "scan": run_scan,
    "exploit": run_exploit,
    "postex": run_postex,
    "lateral": run_lateral,
    "credential": run_credential,
    "exfil": run_exfil,
    "phish": run_phish,
}

__all__ = [
    "Finding", "PhaseResult", "Severity",
    "run_recon", "run_scan", "run_exploit",
    "run_postex", "run_lateral", "run_credential",
    "run_exfil", "run_phish",
    "PHASE_EXECUTORS",
]
