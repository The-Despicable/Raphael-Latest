"""Raphael CI/CD API — FastAPI application entrypoint."""

import asyncio, logging, os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from orchestrator.api.ci import router as ci_router
from orchestrator.engagement_queue import get_queue
from orchestrator.modes.autonomous import handle as autonomous_handle
from orchestrator.webhook import deliver as deliver_webhook

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

        logger.info(f"Processing engagement {eng.id} -> {eng.target}")
        eng.current_phase = eng.phases[0] if eng.phases else "recon"
        try:
            result = await autonomous_handle(eng.target, eng.phases)
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
