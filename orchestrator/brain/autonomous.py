import asyncio, time, logging, os, json

from orchestrator.audit_trail import record_event
from orchestrator.brain.phases.recon import run_recon
from orchestrator.brain.phases.scan import run_scan
from orchestrator.brain.phases.exploit import run_exploit
from orchestrator.brain.phases.postex import run_postex
from orchestrator.brain.phases.lateral import run_lateral
from orchestrator.brain.phases.credential import run_credential
from orchestrator.brain.phases.exfil import run_exfil
from orchestrator.brain.phases.phish import run_phish
from orchestrator.brain.adaptive_brain import AdaptiveBrain
from orchestrator.brain.neural_memory import NeuralMemory, store_episodic, retrieve_episodic, record_schema_drift
from orchestrator.brain.schema_registry import SchemaRegistry
from orchestrator.brain.anonymity_guard import AnonymityGuard
from orchestrator.brain.target_profiler import TargetProfiler

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
}

PHASE_DESCRIPTIONS = {
    "recon":       "Reconnaissance",
    "scan":        "Vulnerability scanning",
    "exploit":     "Exploitation & payload delivery",
    "postex":      "Post-exploitation & C2 deployment",
    "lateral":     "Lateral movement",
    "credential":  "Credential harvesting",
    "exfil":       "Data exfiltration",
    "phish":       "Phishing operations",
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
        if not guard.enforce(allow_skip=False):
            return {"error": "Anonymity verification failed"}

    profile = profiler.profile(target)
    memory.store_target_profile(target, profile)
    brain.update_target_context(target, profile)

    results = {}
    all_findings = []
    for phase in phases:
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

        if not success and brain.should_abort(phase, target):
            logger.warning(f"Brain aborted after phase '{phase}' failure")
            break

    report = brain.generate_report(target, results, None)
    return {
        "target": target,
        "phases_completed": list(results.keys()),
        "results": results,
        "findings_count": len(all_findings),
        "report": report,
    }
