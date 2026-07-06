from .models import Finding, PhaseResult, Severity
from .recon import run_recon
from .scan import run_scan
from .exploit import run_exploit
from .postex import run_postex
from .exfil import run_exfil
from .phish import run_phish

PHASE_EXECUTORS = {
    "recon": run_recon,
    "scan": run_scan,
    "exploit": run_exploit,
    "postex": run_postex,
    "exfil": run_exfil,
    "phish": run_phish,
}

__all__ = [
    "Finding", "PhaseResult", "Severity",
    "run_recon", "run_scan", "run_exploit",
    "run_postex", "run_exfil", "run_phish",
    "PHASE_EXECUTORS",
]
