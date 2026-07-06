import asyncio, time, logging, os, json
import httpx
from .adaptive_brain import AdaptiveBrain
from .neural_memory import NeuralMemory, store_episodic, retrieve_episodic, record_schema_drift
from .schema_registry import SchemaRegistry
from .anonymity_guard import AnonymityGuard
from .target_profiler import TargetProfiler

logger = logging.getLogger("autonomous")

PIPELINE_MAP = {
    "recon":   ("/recon/run",     "recon-pipeline", 3503),
    "scan":    ("/agent/scan",    "cai-service",    3200),
    "exploit": ("/sword/run",     "sword",          3600),
    "postex":  ("/agent/forensic","cai-service",    3200),
    "exfil":   ("/agent/exploit", "cai-service",    3200),
    "phish":   ("/set/send_email","phishing",        3502),
}


async def execute_phase(phase: str, target: str, strategy: dict,
                        api_key: str, registry: SchemaRegistry,
                        memory: NeuralMemory) -> dict:
    if phase not in PIPELINE_MAP:
        return {"success": False, "error": f"Unknown phase: {phase}"}

    path, svc_name, port = PIPELINE_MAP[phase]
    host = os.getenv("PIPELINE_HOST", "127.0.0.1")
    url = f"http://{host}:{port}{path}"

    svc = registry.services.get(svc_name)
    if svc and not svc.available:
        return {"success": False, "error": f"{svc_name} schema unavailable — skipping phase"}

    payload = registry.build_payload(phase, path, svc_name, target, strategy)
    valid, error, cleaned = registry.validate_payload(svc_name, path, payload)
    if not valid:
        logger.warning(f"Payload validation failed for {phase}: {error}")
        return {"success": False, "error": f"payload validation: {error}"}

    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=600) as client:
            resp = await client.post(url, json=cleaned)
        latency = time.time() - t0

        if resp.status_code == 200:
            data = resp.json()
            return {"success": True, "latency": latency, "data": data}

        if resp.status_code == 422:
            schema_hash = registry.schema_hash(svc_name)
            memory.record_schema_drift(
                service=svc_name, path=path,
                declared_schema_hash=schema_hash,
                field_errors=resp.text,
                payload_sent=cleaned,
            )
            logger.warning(f"{phase} 422 — schema drift recorded ({schema_hash})")

        return {"success": False, "latency": latency, "error": resp.text}
    except Exception as e:
        latency = time.time() - t0
        return {"success": False, "latency": latency, "error": str(e)}


async def run_autonomous_engagement(target: str, phases: list, api_key: str,
                                    enforce_anonymity: bool = True) -> dict:
    host = os.getenv("PIPELINE_HOST", "127.0.0.1")
    registry = SchemaRegistry(PIPELINE_MAP, host=host)
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
    for phase in phases:
        ctx = retrieve_episodic(target=target, event_type=phase, limit=5)
        model, strategy = brain.select_model(phase, target, {"context": ctx})
        logger.info(f"Phase {phase}: model={model} strategy={strategy}")

        result = await execute_phase(phase, target, strategy, api_key, registry, memory)
        success = result.get("success", False)
        latency = result.get("latency", 0)

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
        "report": report,
    }
