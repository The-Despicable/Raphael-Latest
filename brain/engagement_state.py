"""Engagement state management — resume, checkpoint, and recovery."""

import json, logging, os, shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("engagement_state")

ENGAGEMENTS_DIR = Path("/engagements")


def resolve_engagement_dir(target_id: Optional[str] = None) -> Optional[Path]:
    """Find the active engagement directory.
    Priority: explicit target_id > .active marker > most recent."""
    if target_id:
        d = ENGAGEMENTS_DIR / target_id
        if d.exists():
            return d
        return None

    active = ENGAGEMENTS_DIR / ".active"
    if active.exists():
        target = active.read_text().strip()
        d = ENGAGEMENTS_DIR / target
        if d.exists():
            return d

    dirs = sorted(ENGAGEMENTS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    for d in dirs:
        if d.is_dir() and (d / "scope.json").exists():
            return d
    return None


def create_engagement(target: str, phases: list[str]) -> Path:
    """Create a new engagement directory with initial state files."""
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    hostname = target.replace("://", "_").replace("/", "_").replace(".", "-")
    eng_dir = ENGAGEMENTS_DIR / f"{ts}-{hostname}"
    eng_dir.mkdir(parents=True, exist_ok=True)

    scope = {
        "target": target,
        "status": "in_progress",
        "current_phase": phases[0] if phases else "recon",
        "phases_completed": [],
        "phases_remaining": phases[1:] if len(phases) > 1 else [],
        "start_time": ts,
        "end_time": None,
    }
    (eng_dir / "scope.json").write_text(json.dumps(scope, indent=2))

    (eng_dir / "findings.md").write_text("# Findings\n\n")
    (eng_dir / "log.md").write_text(f"# Engagement Log\n\nStarted: {ts}\nTarget: {target}\n\n")
    (eng_dir / "intel.md").write_text("# Intelligence\n\n")
    (eng_dir / "intel-secrets.json").write_text("[]")
    (eng_dir / "auth.json").write_text(json.dumps({"cookies": {}, "headers": {}, "tokens": {}}, indent=2))
    (eng_dir / "surfaces.jsonl").write_text("")

    (ENGAGEMENTS_DIR / ".active").write_text(eng_dir.name)
    logger.info("Created engagement %s -> %s", target, eng_dir)
    return eng_dir


def update_scope(eng_dir: Path, updates: dict):
    scope_path = eng_dir / "scope.json"
    if not scope_path.exists():
        return
    scope = json.loads(scope_path.read_text())
    scope.update(updates)
    scope_path.write_text(json.dumps(scope, indent=2))


def append_log(eng_dir: Path, entry: str):
    log_path = eng_dir / "log.md"
    with open(log_path, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {entry}\n")


def append_finding(eng_dir: Path, finding: str):
    findings_path = eng_dir / "findings.md"
    with open(findings_path, "a") as f:
        f.write(f"{finding}\n\n")


class ResumeManager:
    """Manages engagement resume, checkpointing, and stall recovery."""

    def __init__(self, eng_dir: Optional[Path] = None):
        self.eng_dir = eng_dir

    def load_state(self) -> dict:
        if not self.eng_dir:
            return {}
        scope_path = self.eng_dir / "scope.json"
        if not scope_path.exists():
            return {}
        return json.loads(scope_path.read_text())

    def get_phase(self) -> str:
        return self.load_state().get("current_phase", "recon")

    def get_status(self) -> str:
        return self.load_state().get("status", "unknown")

    def advance_phase(self, next_phase: str):
        state = self.load_state()
        completed = state.get("current_phase", "")
        phases_completed = state.get("phases_completed", [])
        if completed and completed not in phases_completed:
            phases_completed.append(completed)
        remaining = state.get("phases_remaining", [])
        if next_phase in remaining:
            remaining.remove(next_phase)
        update_scope(self.eng_dir, {
            "current_phase": next_phase,
            "phases_completed": phases_completed,
            "phases_remaining": remaining,
        })

    def is_stale(self, threshold_minutes: int = 10) -> bool:
        state = self.load_state()
        if state.get("status") == "complete":
            return False
        log_path = self.eng_dir / "log.md"
        if not log_path.exists():
            return True
        mtime = log_path.stat().st_mtime
        age = (datetime.now().timestamp() - mtime) / 60
        return age > threshold_minutes

    def finalize(self):
        update_scope(self.eng_dir, {
            "status": "complete",
            "current_phase": "complete",
            "end_time": datetime.now().isoformat(),
        })
        append_log(self.eng_dir, "Engagement finalized.")
