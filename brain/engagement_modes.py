"""Engagement mode split — interactive (engage) vs autonomous (autoengage)."""

import json, logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("engagement_modes")


class EngagementMode(Enum):
    INTERACTIVE = "engage"
    AUTONOMOUS = "autoengage"


class AuthMethod(Enum):
    PROXY = "proxy"
    COOKIE = "cookie"
    HEADER = "header"
    SKIP = "skip"
    AUTO = "auto"


@dataclass
class PhaseConfig:
    name: str
    parallel: bool = True
    requires_approval: bool = True
    auto_proceed: bool = False


PHASE_DEFINITIONS = {
    "recon": PhaseConfig("recon", parallel=True, requires_approval=False),
    "scan": PhaseConfig("scan", parallel=False, requires_approval=False),
    "exploit": PhaseConfig("exploit", parallel=True, requires_approval=False),
    "postex": PhaseConfig("postex", parallel=False, requires_approval=False),
    "exfil": PhaseConfig("exfil", parallel=False, requires_approval=False),
    "phish": PhaseConfig("phish", parallel=True, requires_approval=False),
    "report": PhaseConfig("report", parallel=False, requires_approval=True),
}


@dataclass
class EngagementConfig:
    target: str
    mode: EngagementMode = EngagementMode.INTERACTIVE
    auth: AuthMethod = AuthMethod.SKIP
    phases: list[str] = field(default_factory=lambda: ["recon", "scan", "exploit", "postex"])
    parallel_by_default: bool = True
    auto_register: bool = False
    auto_use_creds: bool = False
    max_parallel_batches: int = 3

    @classmethod
    def from_target(cls, target: str, auto: bool = False, **kwargs) -> "EngagementConfig":
        if auto:
            return cls(
                target=target,
                mode=EngagementMode.AUTONOMOUS,
                auth=AuthMethod.AUTO,
                parallel_by_default=True,
                auto_register=True,
                auto_use_creds=True,
                **kwargs
            )
        return cls(
            target=target,
            mode=EngagementMode.INTERACTIVE,
            **kwargs
        )


class EngagementController:
    """Controls engagement flow based on mode (interactive vs autonomous)."""

    def __init__(self, config: EngagementConfig, eng_dir: Path):
        self.config = config
        self.eng_dir = eng_dir
        self.is_auto = config.mode == EngagementMode.AUTONOMOUS

    def should_ask_auth(self) -> bool:
        """Interactive mode asks for auth. Auto mode skips or auto-discovers."""
        return not self.is_auto

    def should_ask_approval(self, phase: str) -> bool:
        """Interactive mode asks approval for specific phases. Auto mode never asks."""
        if self.is_auto:
            return False
        config = PHASE_DEFINITIONS.get(phase, PhaseConfig(phase))
        if config.name == "recon":
            return True
        return config.requires_approval

    def should_parallel(self, phase: str) -> bool:
        """Auto mode always parallel. Interactive uses config default."""
        if self.is_auto:
            return True
        config = PHASE_DEFINITIONS.get(phase, PhaseConfig(phase))
        return config.parallel if hasattr(config, 'parallel') else self.config.parallel_by_default

    def get_auth_methods(self) -> list[str]:
        """Get available auth methods based on mode."""
        if self.is_auto:
            return ["auto"]
        return ["proxy", "cookie", "header", "skip"]

    def on_error(self, phase: str, error: str):
        """Handle phase error based on mode."""
        if self.is_auto:
            logger.warning("Auto mode: phase %s error logged, continuing: %s", phase, error)
            self._log_event(f"phase_error", f"{phase}: {error}")
        else:
            logger.error("Interactive mode: stopping on phase %s error: %s", phase, error)
            raise RuntimeError(f"Phase {phase} failed: {error}")

    def on_stop(self) -> dict:
        """Generate stop summary based on mode."""
        state_path = self.eng_dir / "scope.json"
        state = json.loads(state_path.read_text()) if state_path.exists() else {}

        phases_completed = state.get("phases_completed", [])
        current_phase = state.get("current_phase", "")

        stop_reason = "completed"
        if current_phase and current_phase not in phases_completed:
            stop_reason = "incomplete_stop"

        self._log_event("run_stop", f"stop_reason={stop_reason}")

        return {
            "stop_reason": stop_reason,
            "phases_completed": phases_completed,
            "current_phase": current_phase,
            "mode": self.config.mode.value,
        }

    def _log_event(self, event_type: str, message: str):
        log_path = self.eng_dir / "log.md"
        from datetime import datetime
        with open(log_path, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] [{event_type}] {message}\n")


def create_engage_config(target: str) -> EngagementConfig:
    return EngagementConfig.from_target(target, auto=False)


def create_autoengage_config(target: str) -> EngagementConfig:
    return EngagementConfig.from_target(target, auto=True)
