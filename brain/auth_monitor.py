"""Auth monitor — detects new credentials and triggers re-recon."""

import json, logging, os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("auth_monitor")


class AuthMonitor:
    """Monitors credential changes and signals re-recon."""

    def __init__(self, eng_dir: Path):
        self.eng_dir = eng_dir
        self.state_path = eng_dir / ".auth-respawn-state.json"
        self._last_count = self._load_count()

    def _load_count(self) -> int:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text()).get("validated_credentials", 0)
            except (json.JSONDecodeError, ValueError):
                return 0
        return 0

    def _save_count(self, count: int):
        self.state_path.write_text(json.dumps({"validated_credentials": count}))

    def check(self) -> bool:
        """Returns True if new credentials were found since last check."""
        secrets_path = self.eng_dir / "intel-secrets.json"
        if not secrets_path.exists():
            return False

        try:
            secrets = json.loads(secrets_path.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return False

        current = len(secrets)
        if current > self._last_count:
            logger.info("New credentials detected: %d -> %d", self._last_count, current)
            self._save_count(current)
            return True

        return False

    def flag_respawn(self):
        """Touch a flag file that signals the orchestrator to re-recon."""
        flag = self.eng_dir / ".auth-respawn-required"
        flag.touch()

    def clear_respawn_flag(self):
        flag = self.eng_dir / ".auth-respawn-required"
        if flag.exists():
            flag.unlink()

    def respawn_required(self) -> bool:
        flag = self.eng_dir / ".auth-respawn-required"
        return flag.exists()


class IntelMonitor:
    """Monitors intel.md for changes and triggers OSINT re-analysis."""

    def __init__(self, eng_dir: Path):
        self.eng_dir = eng_dir
        self._last_size = self._load_size()

    def _load_size(self) -> int:
        intel_path = self.eng_dir / "intel.md"
        if intel_path.exists():
            return intel_path.stat().st_size
        return 0

    def check(self) -> bool:
        intel_path = self.eng_dir / "intel.md"
        if not intel_path.exists():
            return False
        current = intel_path.stat().st_size
        if current > self._last_size:
            logger.info("intel.md grew: %d -> %d bytes", self._last_size, current)
            self._last_size = current
            return True
        return False

    def flag_respawn(self):
        flag = self.eng_dir / ".osint-respawn-required"
        flag.touch()

    def respawn_required(self) -> bool:
        flag = self.eng_dir / ".osint-respawn-required"
        return flag.exists()
