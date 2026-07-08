import asyncio, json, logging, os, time, uuid
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("engagement_queue")

ENGAGEMENTS_FILE = os.getenv("ENGAGEMENTS_FILE", os.path.join(os.path.dirname(__file__), "..", "..", "data", "engagements.json"))


@dataclass
class Engagement:
    id: str
    target: str
    phases: list
    status: str = "queued"
    current_phase: str = ""
    phases_completed: list = field(default_factory=list)
    c2_session_ids: list = field(default_factory=list)
    findings_count: int = 0
    error: str = ""
    created_at: str = ""
    updated_at: str = ""
    result: dict = field(default_factory=dict)
    persona: str = ""
    webhook_url: str = ""


class EngagementQueue:
    def __init__(self, persist_path: str = ENGAGEMENTS_FILE):
        self._path = persist_path
        self._engagements: list[Engagement] = []
        self._stop = asyncio.Event()
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    data = json.load(f)
                self._engagements = [Engagement(**e) for e in data.get("engagements", [])]
            except Exception as e:
                logger.warning(f"Failed to load engagements: {e}")

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, "w") as f:
                json.dump({"engagements": [asdict(e) for e in self._engagements]}, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save engagements: {e}")

    def enqueue(self, target: str, phases: list[str], c2_init: str = "auto",
                persona: str = "", webhook_url: str = "") -> str:
        eng_id = uuid.uuid4().hex[:12]
        now = datetime.utcnow().isoformat()
        eng = Engagement(
            id=eng_id, target=target, phases=phases,
            status="queued", created_at=now, updated_at=now,
            persona=persona, webhook_url=webhook_url,
        )
        self._engagements.append(eng)
        self._save()
        return eng_id

    def dequeue(self) -> Optional[Engagement]:
        for i, e in enumerate(self._engagements):
            if e.status == "queued":
                e.status = "in_progress"
                e.updated_at = datetime.utcnow().isoformat()
                self._save()
                return e
        return None

    def update(self, eng_id: str, **kwargs):
        for e in self._engagements:
            if e.id == eng_id:
                for k, v in kwargs.items():
                    setattr(e, k, v)
                e.updated_at = datetime.utcnow().isoformat()
                self._save()
                return
        logger.warning(f"Engagement {eng_id} not found for update")

    def get(self, eng_id: str) -> Optional[Engagement]:
        for e in self._engagements:
            if e.id == eng_id:
                return e
        return None

    def list(self, status: str = None) -> list[Engagement]:
        if status:
            return [e for e in self._engagements if e.status == status]
        return list(self._engagements)

    async def run_loop(self, executor):
        self._stop.clear()
        while not self._stop.is_set():
            eng = self.dequeue()
            if not eng:
                await asyncio.sleep(5)
                continue
            logger.info(f"Starting engagement {eng.id} -> {eng.target}")
            eng.current_phase = eng.phases[0] if eng.phases else "recon"
            try:
                result = await executor(eng.target, eng.phases)
                eng.result = result
                eng.findings_count = result.get("total_findings", 0)
                eng.status = "complete"
                c2_sessions = result.get("phases", {}).get("postex", {}).get("c2_sessions", [])
                eng.c2_session_ids = c2_sessions
            except Exception as e:
                eng.status = "failed"
                eng.error = str(e)
            eng.updated_at = datetime.utcnow().isoformat()
            self._save()
            logger.info(f"Engagement {eng.id} finished: {eng.status}")

    def stop(self):
        self._stop.set()

    def clear(self):
        self._engagements.clear()
        self._save()

    def stats(self) -> dict:
        return {
            "total": len(self._engagements),
            "queued": sum(1 for e in self._engagements if e.status == "queued"),
            "in_progress": sum(1 for e in self._engagements if e.status == "in_progress"),
            "complete": sum(1 for e in self._engagements if e.status == "complete"),
            "failed": sum(1 for e in self._engagements if e.status == "failed"),
        }


_queue: Optional[EngagementQueue] = None


def get_queue() -> EngagementQueue:
    global _queue
    if _queue is None:
        _queue = EngagementQueue()
    return _queue
