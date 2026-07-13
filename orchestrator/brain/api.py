import asyncio, json, logging, time, hashlib, os, sys

sys.path.insert(0, "/raphael")
sys.path.insert(1, os.path.dirname(__file__))

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List
import uvicorn

from brain.adaptive_brain import AdaptiveBrain
from brain.neural_memory import NeuralMemory, retrieve_episodic, store_episodic, store_target_profile, get_target_profile
from brain.target_profiler import TargetProfiler
from orchestrator.providers import call_model
from orchestrator.brain.phases import PHASE_EXECUTORS, Finding, PhaseResult

app = FastAPI(title="Raphael Autonomous Brain", version="2.0.0")
brain = AdaptiveBrain()
memory = NeuralMemory()
profiler = TargetProfiler()

PHASES = ["recon", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"]


class StartRequest(BaseModel):
    target: str
    phases: Optional[List[str]] = None
    use_llm_strategist: Optional[bool] = True


class EngageRequest(BaseModel):
    target: str
    phases: Optional[List[str]] = None


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
    use_llm = req.use_llm_strategist

    results = {
        "target": target,
        "phases": {},
        "analytics": {},
        "profile": {},
        "timestamp": time.time(),
        "chain_hash": hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12],
    }

    try:
        profile = profiler.profile(target)
        results["profile"] = profile
        store_target_profile(target, profile.get("classification", {}))
    except Exception as e:
        results["profile"] = {"error": str(e)}

    all_findings: list[Finding] = []

    for phase_name in phases:
        executor = PHASE_EXECUTORS.get(phase_name)
        if not executor:
            results["phases"][phase_name] = {
                "success": False, "error": f"No executor for phase: {phase_name}",
            }
            continue

        t0 = time.time()
        try:
            phase_result: PhaseResult = await executor(target, all_findings)
        except Exception as e:
            phase_result = PhaseResult(
                phase=phase_name, success=False,
                error=str(e), latency=time.time() - t0,
            )

        all_findings.extend(phase_result.findings)

        # LLM strategist: analyzes findings and suggests next-phase strategy
        strategist_output = ""
        if use_llm and phase_result.success and phase_result.findings:
            try:
                finding_summary = "\n".join(
                    f"- [{f.severity.value}] {f.type}: {f.description[:200]}"
                    for f in phase_result.findings[:10]
                )
                strat_msgs = [{"role": "user", "content": (
                    f"[STRATEGIST — {phase_name.upper()} RESULTS]\n"
                    f"Target: {target}\n\n"
                    f"Findings:\n{finding_summary}\n\n"
                    f"The next phase is one of: {[p for p in phases if p != phase_name]}\n"
                    "Based on these results, what should the next phase focus on?\n"
                    "Be specific: which ports, endpoints, or vulnerabilities to prioritize."
                )}]
                strategist_output = await call_model("auto", strat_msgs, max_tokens=1024, temperature=0.5)
            except Exception:
                logging.getLogger(__name__).debug("Non-critical error", exc_info=True)

        results["phases"][phase_name] = {
            "success": phase_result.success,
            "findings": [f.to_dict() for f in phase_result.findings],
            "summary": phase_result.summary,
            "latency": round(phase_result.latency, 2),
            "error": phase_result.error,
            "strategist": strategist_output[:1000] if strategist_output else "",
        }

    results["analytics"] = brain.get_state()
    return results


@app.post("/v1/engage/start")
async def start_engagement(req: EngageRequest):
    target = req.target
    phases = req.phases or ["recon", "scan", "exploit", "postex"]

    results = {
        "target": target,
        "phases": {},
        "timestamp": time.time(),
        "chain_hash": hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12],
    }
    all_findings: list[Finding] = []

    for phase_name in phases:
        executor = PHASE_EXECUTORS.get(phase_name)
        if not executor:
            results["phases"][phase_name] = {"success": False, "error": f"No executor: {phase_name}"}
            continue

        t0 = time.time()
        try:
            phase_result: PhaseResult = await executor(target, all_findings)
        except Exception as e:
            phase_result = PhaseResult(phase=phase_name, success=False, error=str(e), latency=time.time() - t0)

        all_findings.extend(phase_result.findings)
        results["phases"][phase_name] = {
            "success": phase_result.success,
            "findings": [f.to_dict() for f in phase_result.findings],
            "summary": phase_result.summary,
            "latency": round(phase_result.latency, 2),
        }

    return results


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
    from orchestrator.providers import BREAKERS, is_online
    online = await is_online()
    try:
        state = brain.get_state()
        models_tracked = len(state.get("models", []))
        chain_steps = state.get("total_chain_steps", 0)
    except Exception:
        models_tracked = 0
        chain_steps = 0
    return {
        "status": "ok",
        "online": online,
        "models_tracked": models_tracked,
        "chain_steps": chain_steps,
        "circuit_breakers": {name: cb.to_dict() for name, cb in BREAKERS.items()},
    }


# Register C2 channel routes
from orchestrator.c2_channel import register_c2_routes
register_c2_routes(app)

# Register session/pivot routes
@app.get("/v1/c2/sessions")
async def c2_sessions():
    from orchestrator.c2.manager import get_c2
    c2 = get_c2()
    sessions = await c2.refresh_sessions()
    return {"sessions": [s.to_dict() for s in sessions], "count": len(sessions)}

@app.post("/v1/c2/{session_id}/exec")
async def c2_exec(session_id: str, command: str = "whoami"):
    from orchestrator.c2.manager import get_c2
    c2 = get_c2()
    result = await c2.execute(session_id, command)
    return {"session_id": session_id, "output": result.output[:5000], "error": result.error}

@app.post("/v1/c2/{session_id}/socks")
async def c2_socks(session_id: str, port: int = 0):
    from orchestrator.c2.manager import get_c2
    c2 = get_c2()
    proxy = await c2.socks_enable(session_id, port)
    return {"session_id": session_id, "proxy": proxy}

@app.get("/v1/ad/status")
async def ad_status():
    from orchestrator.ad.toolkit import get_ad_toolkit
    ad = get_ad_toolkit()
    return {"impacket_available": ad.has_impacket}

@app.get("/v1/pivot/status")
async def pivot_status():
    from orchestrator.pivot.manager import get_pivot
    p = get_pivot()
    return {"chain_length": p.chain_length, "deepest_proxy": p.deepest_proxy}

@app.get("/v1/cli/status")
async def cli_status():
    from orchestrator.brain.session_store import SessionStore
    from orchestrator.c2.manager import get_c2
    store = SessionStore()
    c2 = get_c2()
    sessions = []
    engagements = store.list_active()
    agents = [s.to_dict() for s in c2.active_sessions]
    state = brain.get_state()
    return {
        "engagements": engagements,
        "agents": agents,
        "models_tracked": len(state.get("models", [])),
        "chain_steps": state.get("total_chain_steps", 0),
        "timestamp": time.time(),
    }

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
