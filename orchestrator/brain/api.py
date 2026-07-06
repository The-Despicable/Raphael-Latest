import asyncio, json, time, hashlib, os, sys

sys.path.insert(0, "/raphael")
sys.path.insert(1, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional, List
import uvicorn

from brain.adaptive_brain import AdaptiveBrain, PSOModelSelector, pick_model, get_analytics, record_chain_step
from brain.neural_memory import NeuralMemory, retrieve_episodic, store_episodic, store_target_profile, get_target_profile
from brain.target_profiler import TargetProfiler
from brain.anonymity_guard import AnonymityGuard
from orchestrator.providers import call_model, ALL_ALIASES as ALIASES

app = FastAPI(title="Raphael Autonomous Brain", version="2.0.0")
brain = AdaptiveBrain()
memory = NeuralMemory()
profiler = TargetProfiler()

PHASE_CONTEXT_MAP = {
    "recon": "recon", "scan": "sqli", "exploit": "rce",
    "postex": "rce", "exfil": "phishing", "phish": "phishing",
}
PHASES = ["recon", "scan", "exploit", "postex", "exfil", "phish"]
PHASE_PROMPTS = {
    "recon": "Perform deep reconnaissance on the target. Identify subdomains, DNS records, technologies, open ports.",
    "scan": "Perform vulnerability scanning. Identify CVEs, misconfigurations, weak services.",
    "exploit": "Formulate exploitation strategies based on discovered vulnerabilities.",
    "postex": "Post-exploitation: lateral movement, privilege escalation, persistence.",
    "exfil": "Data exfiltration planning: DNS tunnel, HTTP, SMTP methods.",
    "phish": "Social engineering and phishing campaign design.",
}


class StartRequest(BaseModel):
    target: str
    phases: Optional[List[str]] = None
    rounds: Optional[int] = 1
    no_anonymity: Optional[bool] = False
    use_pso: Optional[bool] = False
    max_tokens: Optional[int] = 4096
    temperature: Optional[float] = 0.85


class ChainRequest(BaseModel):
    chain_hash: str


class ProfileRequest(BaseModel):
    target: str


class StoreMemoryRequest(BaseModel):
    event_type: str
    target: str
    model: str
    context: str
    input_data: str
    output_summary: str
    success: bool
    score: float
    latency: float


class StoreSemanticRequest(BaseModel):
    concept: str
    data: dict
    confidence: Optional[float] = 0.5
    source: Optional[str] = "api"


@app.get("/v1/brain/memory")
async def get_memory(target: str = None, event_type: str = None, limit: int = 50):
    return retrieve_episodic(target=target, event_type=event_type, limit=limit)


@app.post("/v1/brain/memory")
async def add_memory(req: StoreMemoryRequest):
    return {"id": store_episodic(
        req.event_type, req.target, req.model, req.context,
        req.input_data, req.output_summary, req.success, req.score, req.latency,
    )}


@app.post("/v1/brain/semantic")
async def add_semantic(req: StoreSemanticRequest):
    memory.store_semantic(req.concept, req.data, req.confidence, req.source)
    return {"status": "ok"}


@app.post("/v1/autonomous/start")
async def start_autonomous(req: StartRequest):
    target = req.target
    phases = req.phases or PHASES
    no_anonymity = req.no_anonymity
    use_pso = req.use_pso

    results = {
        "target": target,
        "phases": {},
        "analytics": {},
        "anonymity": {},
        "profile": {},
        "timestamp": time.time(),
        "chain_hash": hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12],
    }

    guard = AnonymityGuard(require_tor=not no_anonymity, rotation_interval=300)
    try:
        anon_status = guard.enforce(allow_skip=no_anonymity)
        results["anonymity"] = anon_status
    except RuntimeError as e:
        results["anonymity"] = {"error": str(e), "tor_active": False}
        return results

    try:
        profile = profiler.profile(target)
        results["profile"] = profile
        store_target_profile(target, profile.get("classification", {}))
    except Exception as e:
        results["profile"] = {"error": str(e)}

    candidates = list(ALIASES.keys())
    pso = PSOModelSelector(n_models=len(candidates)) if use_pso else None
    prev_outputs = {}

    for phase_name in phases:
        context = PHASE_CONTEXT_MAP.get(phase_name, "recon")

        if use_pso and pso:
            model_alias = pso.select(context, candidates, iterations=20)
        else:
            model_alias = pick_model(context, candidates)

        phase_prompt = PHASE_PROMPTS.get(phase_name, f"Analyze for {phase_name}.")
        msgs = [{"role": "user", "content": f"[AUTONOMOUS - {phase_name.upper()}]\nTarget: {target}\n"}]
        if prev_outputs:
            summary = "\n".join(f"- {k}: {v[:500]}" for k, v in prev_outputs.items())
            msgs[0]["content"] += f"\nPrevious phase results:\n{summary}\n\n"
        msgs[0]["content"] += f"\n{phase_prompt}"

        t0 = time.time()
        error = False
        try:
            output = await call_model(model_alias, msgs, max_tokens=req.max_tokens, temperature=req.temperature)
        except Exception as e:
            output = f"ERROR: {e}"
            error = True
        latency = time.time() - t0

        success = not error and len(output.strip()) > 20
        brain.update_stats(model_alias, context, success, latency)
        record_chain_step(results["chain_hash"], len(results["phases"]), model_alias, context, 1.0 if success else 0.0, latency)

        store_episodic(phase_name, target, model_alias, context, msgs[0]["content"], output[:2000], success, 1.0 if success else 0.0, latency)
        prev_outputs[phase_name] = output[:2000]

        results["phases"][phase_name] = {
            "model": model_alias, "context": context, "success": success,
            "latency": round(latency, 2), "output": output,
        }

    results["analytics"] = brain.get_state()
    return results


@app.post("/v1/engage/start")
async def start_engagement(req: StartRequest):
    from brain.autonomous import run_autonomous_engagement
    target = req.target
    phases = req.phases or ["recon", "scan", "exploit", "postex"]
    result = await run_autonomous_engagement(
        target, phases,
        api_key=os.getenv("API_KEY", ""),
        enforce_anonymity=not req.no_anonymity,
    )
    return result


@app.get("/v1/brain/state")
async def get_brain_state():
    return brain.get_state()


@app.post("/v1/brain/reset")
async def reset_brain():
    brain.reset()
    return {"status": "ok"}


@app.get("/v1/chain/{chain_hash}")
async def get_chain(chain_hash: str):
    from brain.adaptive_brain import get_chain_history
    return get_chain_history(chain_hash)


@app.get("/v1/health")
async def health():
    state = brain.get_state()
    return {
        "status": "ok",
        "models_tracked": len(state.get("models", [])),
        "chain_steps": state.get("total_chain_steps", 0),
    }


# Register C2 channel routes
from orchestrator.c2_channel import register_c2_routes
register_c2_routes(app)

# Register audit trail routes
class AuditQueryRequest(BaseModel):
    session: Optional[str] = None

@app.get("/v1/audit/stats")
async def audit_stats():
    from orchestrator.audit_trail import audit_stats
    return audit_stats()

@app.get("/v1/audit/log")
async def audit_log(session: str = None):
    from orchestrator.audit_trail import get_session_log
    return {"events": get_session_log(session)}

@app.get("/v1/audit/verify")
async def audit_verify():
    from orchestrator.audit_trail import verify_chain
    return {"issues": verify_chain()}

# Register target state routes
@app.get("/v1/target/state/{target}")
async def target_state(target: str):
    from orchestrator.brain.target_state import get_target_state, summarize_target_state
    return {"state": get_target_state(target), "summary": summarize_target_state(target)}

@app.post("/v1/target/state/{target}/cve/{cve_id}/patch")
async def target_patch_cve(target: str, cve_id: str):
    from orchestrator.brain.target_state import mark_cve_patched
    mark_cve_patched(target, cve_id)
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.getenv("BRAIN_PORT", "3700"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
