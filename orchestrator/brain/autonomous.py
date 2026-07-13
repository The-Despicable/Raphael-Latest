import asyncio, time, logging, os, json, uuid

from orchestrator.audit_trail import record_event
from orchestrator.brain.phases.recon import run_recon
from orchestrator.brain.phases.scan import run_scan
from orchestrator.brain.phases.exploit import run_exploit
from orchestrator.brain.phases.postex import run_postex
from orchestrator.brain.phases.lateral import run_lateral
from orchestrator.brain.phases.credential import run_credential
from orchestrator.brain.phases.exfil import run_exfil
from orchestrator.brain.phases.phish import run_phish
from orchestrator.brain.phases.web_scan import run_web_scan
from orchestrator.brain.phases.generic_exploit import run_generic_exploit
from orchestrator.brain.phases.persistence import run_persistence
from orchestrator.brain.phases.reversing import run_reversing
from orchestrator.brain.phases.web_fuzz import run_web_fuzz
from orchestrator.brain.phases.pivot import run_pivot
from orchestrator.brain.phases.exploit_chain import run_exploit_chain
from orchestrator.brain.phases.stealth import run_stealth
from orchestrator.brain.phases.multitarget import run_multitarget
from orchestrator.brain.phases.reporting import run_reporting
from orchestrator.brain.phases.lpd_exploit import run_lpd_exploit
from orchestrator.brain.phases.flag_capture import run_flag_capture
from orchestrator.brain.adaptive_brain import AdaptiveBrain
from orchestrator.brain.neural_memory import NeuralMemory, store_episodic, retrieve_episodic, record_schema_drift
from orchestrator.brain.schema_registry import SchemaRegistry
from orchestrator.brain.anonymity_guard import AnonymityGuard
from orchestrator.brain.target_profiler import TargetProfiler

try:
    from orchestrator.checkpoint.checkpoint_manager import CheckpointManager
    _checkpoint = CheckpointManager(namespace="autonomous")
except ImportError:
    _checkpoint = None

logger = logging.getLogger("autonomous")

PHASE_RUNNERS = {
    "recon":       run_recon,
    "scan":        run_scan,
    "exploit":     run_exploit,
    "postex":      run_postex,
    "lateral":     run_lateral,
    "credential":  run_credential,
    "exfil":       run_exfil,
    "phish":       run_phish,
    "web_scan":    run_web_scan,
    "generic_exploit": run_generic_exploit,
    "persistence": run_persistence,
    "reversing":   run_reversing,
    "web_fuzz":    run_web_fuzz,
    "exploit_chain": run_exploit_chain,
    "pivot":       run_pivot,
    "stealth":     run_stealth,
    "multitarget": run_multitarget,
    "reporting":   run_reporting,
    "lpd_exploit": run_lpd_exploit,
    "flag_capture": run_flag_capture,
}

PHASE_DESCRIPTIONS = {
    "recon":         "Reconnaissance",
    "scan":          "Vulnerability scanning",
    "exploit":       "Exploitation & payload delivery",
    "web_scan":      "Web application scanning",
    "generic_exploit": "Generic service exploitation (SSH, HTTP, SMB, DB, NFS, Redis)",
    "postex":        "Post-exploitation & C2 deployment",
    "lateral":       "Lateral movement",
    "credential":    "Credential harvesting",
    "persistence":   "Backdoor & persistence deployment",
    "reversing":     "Binary analysis & reverse engineering",
    "exfil":         "Data exfiltration",
    "phish":         "Phishing operations",
    "web_fuzz":      "Deep web application fuzzing (SQLi, XSS, CMDi, SSTI, auth bypass, file upload, path traversal)",
    "exploit_chain": "Automated exploit chaining & state machine",
    "pivot":         "Network pivoting & lateral movement via C2 sessions",
    "stealth":       "Stealth & evasion engine: rate limiting, traffic shaping, log cleaning",
    "multitarget":   "Multi-target coordination: scoring, prioritization, queue management",
    "reporting":     "Auto report generation: Markdown, HTML, JSON export",
    "lpd_exploit":   "LPD print service exploitation & flag capture (callback, HTTP, SSH fallback)",
    "flag_capture":  "Flag capture via webshell, SSH, LPD bind shell, and credential-based extraction",
}


async def execute_phase(phase: str, target: str, strategy: dict,
                        api_key: str, registry: SchemaRegistry,
                        memory: NeuralMemory,
                        previous_findings: list = None) -> dict:
    runner = PHASE_RUNNERS.get(phase)
    if not runner:
        return {"success": False, "error": f"Unknown phase: {phase}"}

    t0 = time.time()
    try:
        result = await runner(target, findings=previous_findings)
        latency = time.time() - t0
        record_event(
            action=f"phase:{phase}",
            target=target,
            phase=phase,
            model=strategy.get("model", "auto"),
            verdict="pass" if result.success else "fail",
            latency=latency,
            error=result.error,
            metadata={"findings_count": len(result.findings), "summary": result.summary},
        )
        return {
            "success": result.success,
            "latency": latency,
            "data": result.to_dict(),
            "findings": result.findings,
        }
    except Exception as e:
        latency = time.time() - t0
        record_event(
            action=f"phase:{phase}",
            target=target,
            phase=phase,
            verdict="fail",
            latency=latency,
            error=str(e),
        )
        return {"success": False, "latency": latency, "error": str(e)}


async def run_autonomous_engagement(target: str, phases: list, api_key: str,
                                    enforce_anonymity: bool = True) -> dict:
    host = os.getenv("PIPELINE_HOST", "127.0.0.1")
    registry = SchemaRegistry({}, host=host)
    brain = AdaptiveBrain()
    memory = NeuralMemory()
    guard = AnonymityGuard()
    profiler = TargetProfiler()

    if enforce_anonymity:
        status = guard.enforce(target=target)
        if not status.get("proxy_ok", False):
            return {"error": "Anonymity verification failed", "details": status}

    profile = profiler.profile(target)
    memory.store_target_profile(target, profile)
    brain.update_target_context(target, profile)

    results = {}
    all_findings = []
    op_id = uuid.uuid4().hex[:12]

    if _checkpoint:
        _checkpoint.save(op_id, {
            "target": target,
            "phases": phases,
            "current_phase": phases[0] if phases else None,
            "phase_index": 0,
            "results": {},
            "all_findings": [],
            "status": "started",
        }, phase="init")

    for idx, phase in enumerate(phases):
        ctx = retrieve_episodic(target=target, event_type=phase, limit=5)
        model, strategy = brain.select_model(phase, target, {"context": ctx})
        logger.info(f"Phase {phase} ({PHASE_DESCRIPTIONS.get(phase, phase)}): model={model} strategy={strategy}")

        result = await execute_phase(phase, target, strategy, api_key, registry, memory,
                                     previous_findings=all_findings)
        success = result.get("success", False)
        latency = result.get("latency", 0)

        phase_findings = result.get("findings", []) or []
        all_findings.extend(phase_findings)

        store_episodic(
            event_type=phase, target=target, model=model, context=phase,
            input_data=json.dumps(strategy),
            output_summary=str(result.get("data", result.get("error", ""))),
            success=success, score=1.0 if success else 0.0, latency=latency,
        )
        brain.update(model, phase, success, latency)
        brain.store_reasoning_chain(phase, target, model, result)

        results[phase] = result

        if _checkpoint:
            _checkpoint.save(op_id, {
                "target": target,
                "phases": phases,
                "current_phase": phase,
                "phase_index": idx,
                "results": {k: {"success": v.get("success"), "latency": v.get("latency")} for k, v in results.items()},
                "all_findings_count": len(all_findings),
                "status": "running",
            }, phase=phase)

        if not success and brain.should_abort(phase, target):
            logger.warning(f"Brain aborted after phase '{phase}' failure")
            break

    report = brain.generate_report(target, results, None)

    if _checkpoint:
        _checkpoint.save(op_id, {
            "target": target,
            "phases": phases,
            "phases_completed": list(results.keys()),
            "findings_count": len(all_findings),
            "status": "completed",
        }, phase="complete")

    return {
        "target": target,
        "phases_completed": list(results.keys()),
        "results": results,
        "findings_count": len(all_findings),
        "report": report,
    }
