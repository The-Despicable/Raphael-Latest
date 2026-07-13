import os
import sys
import json
import logging
from typing import Optional

from orchestrator.checkpoint.checkpoint_manager import CheckpointManager

logger = logging.getLogger("checkpoint.recovery")


class AutoRecovery:
    def __init__(self, namespace: str = "default"):
        self.cpm = CheckpointManager(namespace=namespace)

    def find_incomplete(self) -> list[dict]:
        active = self.cpm.list_active(max_age_hours=24)
        incomplete = [e for e in active if e.get("data", {}).get("status") != "completed"]
        return incomplete

    def resume_data(self, op_id: str) -> Optional[dict]:
        entry = self.cpm.load(op_id)
        if not entry:
            return None
        return entry.get("data")

    def resume_prompt(self) -> Optional[dict]:
        incomplete = self.find_incomplete()
        if not incomplete:
            return None
        latest = incomplete[0]
        logger.info(f"  Found incomplete operation: {latest['op_id']}")
        logger.info(f"  Phase: {latest.get('phase')}")
        logger.info(f"  Target: {latest.get('data', {}).get('target', 'unknown')}")
        return self.resume_data(latest["op_id"])

    def mark_completed(self, op_id: str):
        entry = self.cpm.load(op_id)
        if entry:
            entry.setdefault("data", {})["status"] = "completed"
            self.cpm.save(op_id, entry["data"])

    def cleanup_stale(self, max_age_hours: int = 24):
        self.cpm.cleanup(max_age_hours=max_age_hours)
