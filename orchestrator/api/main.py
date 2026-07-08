"""Raphael CI/CD API — FastAPI application entrypoint."""

import asyncio, logging, os, time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from orchestrator.api.ci import router as ci_router
from orchestrator.engagement_queue import get_queue
from orchestrator.modes.autonomous import handle as autonomous_handle
from orchestrator.webhook import deliver as deliver_webhook
from orchestrator.hardening.rate_limiter import get_limiter
from orchestrator.audit_trail import record_event

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ci_api_main")

app = FastAPI(title="Raphael CI/CD API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        limiter = get_limiter()
        await limiter.wait(key=f"api:{client_ip}")
        response = await call_next(request)
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        t0 = time.time()
        response = await call_next(request)
        latency = time.time() - t0

        if request.url.path.startswith("/v1/ci/"):
            record_event(
                action=f"{request.method} {request.url.path}",
                target=request.url.path,
                phase="ci_api",
                verdict="success" if response.status_code < 400 else "error",
                latency=latency,
                metadata={"status_code": response.status_code, "client_ip": request.client.host if request.client else "unknown"},
            )
        return response


app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditLogMiddleware)

app.include_router(ci_router)


@app.on_event("startup")
async def startup():
    queue = get_queue()
    asyncio.create_task(_engage_worker(queue))
    logger.info("CI/CD API started — engagement worker running")


async def _engage_worker(queue):
    while True:
        eng = queue.dequeue()
        if not eng:
            await asyncio.sleep(5)
            continue

        logger.info(f"Processing engagement {eng.id} -> {eng.target} (persona={eng.persona or 'default'})")
        eng.current_phase = eng.phases[0] if eng.phases else "recon"
        try:
            result = await autonomous_handle(eng.target, eng.phases, persona=eng.persona)
            eng.result = result
            eng.findings_count = result.get("total_findings", 0)
            eng.status = "complete"
            c2_sessions = result.get("phases", {}).get("postex", {}).get("c2_sessions", [])
            eng.c2_session_ids = c2_sessions

            if getattr(eng, "webhook_url", None):
                asyncio.create_task(deliver_webhook(eng.webhook_url, {
                    "event": "engagement.complete",
                    "id": eng.id,
                    "target": eng.target,
                    "status": "complete",
                    "findings_count": eng.findings_count,
                }))
        except Exception as e:
            eng.status = "failed"
            eng.error = str(e)
            logger.exception(f"Engagement {eng.id} failed: {e}")
            if getattr(eng, "webhook_url", None):
                asyncio.create_task(deliver_webhook(eng.webhook_url, {
                    "event": "engagement.failed",
                    "id": eng.id,
                    "target": eng.target,
                    "status": "failed",
                    "error": str(e),
                }))
        eng.updated_at = __import__("datetime").datetime.utcnow().isoformat()
        logger.info(f"Engagement {eng.id} finished: {eng.status}")


if __name__ == "__main__":
    port = int(os.getenv("CI_API_PORT", "3900"))
    uvicorn.run(app, host="0.0.0.0", port=port)
