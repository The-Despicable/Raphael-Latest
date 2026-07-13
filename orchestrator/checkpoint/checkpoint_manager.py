import json
import os
import time
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("checkpoint")

CHECKPOINT_DIR = os.getenv("CHECKPOINT_DIR", "/tmp/raphael_checkpoints")


class CheckpointManager:
    def __init__(self, namespace: str = "default", checkpoint_dir: str = None):
        self.namespace = namespace
        self.checkpoint_dir = Path(checkpoint_dir or CHECKPOINT_DIR) / namespace
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._session_store = None

    def _lazy_store(self):
        if self._session_store is None:
            try:
                from orchestrator.brain.session_store import SessionStore
                self._session_store = SessionStore()
            except ImportError:
                self._session_store = None
        return self._session_store

    def save(self, op_id: str, data: dict, phase: str = None):
        entry = {
            "op_id": op_id,
            "phase": phase,
            "timestamp": time.time(),
            "data": data,
        }
        path = self.checkpoint_dir / f"{op_id}.json"
        with open(path, "w") as f:
            json.dump(entry, f, default=str)
        store = self._lazy_store()
        if store:
            try:
                store.save(op_id, {
                    "target": data.get("target", ""),
                    "phases": data.get("phases", []),
                    "current_phase": phase or data.get("current_phase"),
                    "results": data.get("results", {}),
                    "state": {"namespace": self.namespace, "op_id": op_id},
                })
            except Exception as e:
                logger.debug(f"  SessionStore save failed: {e}")
        logger.info(f"  Checkpoint saved: {self.namespace}/{op_id} (phase={phase})")

    def load(self, op_id: str) -> Optional[dict]:
        path = self.checkpoint_dir / f"{op_id}.json"
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def delete(self, op_id: str):
        path = self.checkpoint_dir / f"{op_id}.json"
        if path.exists():
            path.unlink()
        store = self._lazy_store()
        if store:
            try:
                store.delete(op_id)
            except Exception:
                logger.debug("Non-critical error", exc_info=True)

    def list_active(self, max_age_hours: int = 24) -> list[dict]:
        results = []
        now = time.time()
        cutoff = now - (max_age_hours * 3600)
        for path in sorted(self.checkpoint_dir.glob("*.json"), key=os.path.getmtime, reverse=True):
            try:
                with open(path) as f:
                    entry = json.load(f)
                if entry.get("timestamp", 0) > cutoff:
                    results.append(entry)
            except (json.JSONDecodeError, OSError):
                continue
        return results

    def cleanup(self, max_age_hours: int = 24):
        now = time.time()
        cutoff = now - (max_age_hours * 3600)
        for path in list(self.checkpoint_dir.glob("*.json")):
            try:
                if os.path.getmtime(path) < cutoff:
                    path.unlink()
            except OSError:
                continue
        logger.info(f"  Cleaned checkpoints older than {max_age_hours}h")

    def find_by_target(self, target: str) -> list[dict]:
        return [e for e in self.list_active() if e.get("data", {}).get("target") == target]
