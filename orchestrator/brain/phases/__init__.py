from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
from orchestrator.brain.phases.recon import run_recon
from orchestrator.brain.phases.scan import run_scan
from orchestrator.brain.phases.exploit import run_exploit
from orchestrator.brain.phases.postex import run_postex
from orchestrator.brain.phases.lateral import run_lateral
from orchestrator.brain.phases.credential import run_credential
from orchestrator.brain.phases.exfil import run_exfil
from orchestrator.brain.phases.phish import run_phish
from orchestrator.brain.phases.llm_exploit import run_llm_exploit
from orchestrator.brain.phases.direct_exploit import run_direct_exploit
from orchestrator.brain.phases.privesc import run_privesc
from orchestrator.brain.phases.flag_capture import run_flag_capture
from orchestrator.brain.phases.craft_exploit import run_craft_exploit
from orchestrator.brain.phases.openstamanager_exploit import run_openstamanager_exploit
from orchestrator.brain.phases.lpd_exploit import run_lpd_exploit
from orchestrator.brain.phases.web_scan import run_web_scan
from orchestrator.brain.phases.generic_exploit import run_generic_exploit
from orchestrator.brain.phases.persistence import run_persistence
from orchestrator.brain.phases.reversing import run_reversing, run_binary_analysis
from orchestrator.brain.phases.web_fuzz import run_web_fuzz
from orchestrator.brain.phases.exploit_chain import run_exploit_chain, run_exploit_chaining
from orchestrator.brain.phases.pivot import run_pivot
from orchestrator.brain.phases.stealth import run_stealth
from orchestrator.brain.phases.multitarget import run_multitarget
from orchestrator.brain.phases.reporting import run_reporting, run_generate_report
from orchestrator.brain.phases.pjl_exploit import run_pjl_exploit
from orchestrator.brain.phases.socket_scm import run_socket_scm
from orchestrator.brain.phases.honeypot_analyzer import run_honeypot_analyzer
from orchestrator.exploit.relay_chain import run_relay_chain


async def _lazy_anonymous_ttp(target, findings=None):
    from orchestrator.tactics.anonymous_ttp import run_anonymous_ttp
    return await run_anonymous_ttp(target, findings)

async def _lazy_harvest(target, findings=None):
    from orchestrator.harvester.phase_harvest import run_harvest
    return await run_harvest(target, findings)

PHASE_EXECUTORS = {
    "recon": run_recon,
    "scan": run_scan,
    "exploit": run_exploit,
    "postex": run_postex,
    "lateral": run_lateral,
    "credential": run_credential,
    "exfil": run_exfil,
    "phish": run_phish,
    "llm_exploit": run_llm_exploit,
    "direct_exploit": run_direct_exploit,
    "privesc": run_privesc,
    "flag_capture": run_flag_capture,
    "craft_exploit": run_craft_exploit,
    "openstamanager_exploit": run_openstamanager_exploit,
    "lpd_exploit": run_lpd_exploit,
    "web_scan": run_web_scan,
    "generic_exploit": run_generic_exploit,
    "persistence": run_persistence,
    "reversing": run_reversing,
    "binary_analysis": run_binary_analysis,
    "web_fuzz": run_web_fuzz,
    "exploit_chain": run_exploit_chain,
    "exploit_chaining": run_exploit_chaining,
    "pivot": run_pivot,
    "stealth": run_stealth,
    "multitarget": run_multitarget,
    "reporting": run_reporting,
    "generate_report": run_generate_report,
    "pjl_exploit": run_pjl_exploit,
    "socket_scm": run_socket_scm,
    "honeypot_analyzer": run_honeypot_analyzer,
    "relay_chain": run_relay_chain,
    "anonymous_ttp": _lazy_anonymous_ttp,
    "harvest": _lazy_harvest,
}

__all__ = [
    "Finding", "PhaseResult", "Severity",
    "run_recon", "run_scan", "run_exploit",
    "run_postex", "run_lateral", "run_credential",
    "run_exfil", "run_phish",
    "run_llm_exploit", "run_direct_exploit", "run_privesc", "run_flag_capture",
    "run_craft_exploit", "run_openstamanager_exploit",
    "run_lpd_exploit", "run_web_scan", "run_generic_exploit", "run_persistence",
    "run_reversing", "run_binary_analysis", "run_web_fuzz",
    "run_exploit_chain", "run_exploit_chaining",
    "run_pivot",
    "run_stealth", "run_multitarget", "run_reporting", "run_generate_report",
    "run_pjl_exploit", "run_socket_scm", "run_honeypot_analyzer", "run_relay_chain",
    "run_anonymous_ttp",
    "PHASE_EXECUTORS",
]
