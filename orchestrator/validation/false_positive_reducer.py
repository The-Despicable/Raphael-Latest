import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("false_positive_reducer")

HISTORY_DIR = Path(
    os.getenv("VALIDATION_HISTORY_DIR", "/tmp/validation_history")
)

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.0,
}

# Scoring rules: each returns a deduction (0-1) or None if not applicable
RULES: list[tuple[str, callable]] = []


def _register_rule(name: str, fn: callable):
    RULES.append((name, fn))


@dataclass
class ScoredFinding:
    finding: dict
    score: float = 0.0
    rule_hits: list[str] = field(default_factory=list)
    rejected: bool = False
    rejection_reason: str = ""


def _parse_rule(score: float) -> str:
    if score >= 0.8:
        return "very_likely_fp"
    if score >= 0.5:
        return "likely_fp"
    if score >= 0.3:
        return "possible_fp"
    return "likely_valid"


# ── Scoring Rules ───────────────────────────────────────────


def _rule_no_port(finding: dict) -> Optional[float]:
    """Findings without a port or service reference are suspicious."""
    ftype = finding.get("type", "").lower()
    if ftype in ("open_port", "service_discovery", "service_discovered"):
        return None
    port = finding.get("port")
    service = finding.get("service")
    if not port and not service:
        return 0.4
    return None


def _rule_generic_error(finding: dict) -> Optional[float]:
    """Findings with generic error messages are often FP."""
    desc = (finding.get("description", "") + " " + finding.get("evidence", "")).lower()
    generic = [
        "error occurred", "something went wrong", "internal error",
        "unexpected error", "an error has occurred",
    ]
    if any(g in desc for g in generic):
        return 0.6
    return None


def _rule_time_based_only(finding: dict) -> Optional[float]:
    """Time-based SQLi findings without other evidence are high FP."""
    desc = (finding.get("description", "") + " " + finding.get("evidence", "")).lower()
    if "time" in desc and "delay" in desc:
        if not any(p in desc for p in ("error", "output", "data", "table")):
            return 0.7
    return None


def _rule_no_reflection(finding: dict) -> Optional[float]:
    """XSS findings without reflection evidence are suspicious."""
    ftype = finding.get("type", "").lower()
    if "xss" not in ftype:
        return None
    desc = (finding.get("description", "") + " " + finding.get("evidence", ""))
    if "<script>" not in desc and "alert(" not in desc and "onerror" not in desc:
        return 0.5
    return None


def _rule_severity_mismatch(finding: dict) -> Optional[float]:
    """Auto-assigned severity that doesn't match the evidence."""
    severity = finding.get("severity", "").lower()
    desc = (finding.get("description", "") + " " + finding.get("evidence", "")).lower()
    if severity == "critical" and len(desc) < 50:
        return 0.3
    return None


# Register rules
_register_rule("no_port_or_service", _rule_no_port)
_register_rule("generic_error_message", _rule_generic_error)
_register_rule("time_based_only", _rule_time_based_only)
_register_rule("no_xss_reflection", _rule_no_reflection)
_register_rule("severity_mismatch", _rule_severity_mismatch)


class FalsePositiveReducer:
    """Scores findings against heuristic rules and feeds rejected ones
    back to the RL strategy learner (with warm-up guard).
    """

    REJECT_THRESHOLD = 0.5

    def __init__(self):
        self._rejected_count = 0
        os.makedirs(HISTORY_DIR, exist_ok=True)

    def score_finding(self, finding: dict) -> ScoredFinding:
        score = 0.0
        hits = []
        for name, rule_fn in RULES:
            try:
                deduction = rule_fn(finding)
                if deduction is not None:
                    score += deduction
                    hits.append(name)
            except Exception as e:
                logger.debug(f"Rule '{name}' error: {e}")

        score = min(1.0, score)
        rejected = score >= self.REJECT_THRESHOLD
        reason = _parse_rule(score) if rejected else ""

        return ScoredFinding(
            finding=finding,
            score=round(score, 2),
            rule_hits=hits,
            rejected=rejected,
            rejection_reason=reason,
        )

    def reduce(
        self, findings: list[dict], target: str
    ) -> tuple[list[dict], list[ScoredFinding]]:
        """Split findings into accepted and rejected lists.

        Returns:
            (accepted_findings, rejected_scored_findings)
        """
        accepted = []
        rejected_sf: list[ScoredFinding] = []

        for f in findings:
            sf = self.score_finding(f)
            if sf.rejected:
                rejected_sf.append(sf)
            else:
                accepted.append(f)

        self._log_rejected(rejected_sf, target)
        return accepted, rejected_sf

    def _log_rejected(self, rejected: list[ScoredFinding], target: str):
        """Log rejected findings with warm-up guard for RL feedback."""
        if not rejected:
            return

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "target": target,
            "rejected_count": len(rejected),
            "rejected_types": [
                {
                    "type": sf.finding.get("type", "unknown"),
                    "score": sf.score,
                    "rules": sf.rule_hits,
                    "reason": sf.rejection_reason,
                }
                for sf in rejected
            ],
        }

        log_file = HISTORY_DIR / f"rejected_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # WARM-UP GUARD: Don't feed back to RL until we have 20 episodes
        try:
            from orchestrator.brain.strategy_learner import get_strategy_learner
            learner = get_strategy_learner()
            stats = learner.get_stats()

            if stats.get("episode_count", 0) < 20:
                logger.debug(
                    f"RL warm-up ({stats.get('episode_count', 0)}/20 episodes) — "
                    f"skipping FP feedback to avoid overwriting seeded values"
                )
                return

            for sf in rejected:
                learner.record_outcome(
                    success=False,
                    findings=[sf.finding],
                    phase_name=sf.finding.get("type", "unknown"),
                    latency=0.0,
                    timeout=False,
                    breaker=False,
                )
            logger.info(
                f"Fed {len(rejected)} rejected findings back to RL learner "
                f"(episode {stats.get('episode_count', '?')})"
            )
        except Exception as e:
            logger.debug(f"RL feedback error: {e}")

    def get_rejected_count(self) -> int:
        return self._rejected_count
