import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_multitarget")


class TargetPriority(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


@dataclass
class ScoredTarget:
    ip: str
    hostname: str = ""
    ports_open: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os: str = ""
    domain: str = ""
    priority: TargetPriority = TargetPriority.MEDIUM
    score: float = 0.0
    vulnerable: bool = False
    exploited: bool = False
    completed_phases: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def key(self) -> str:
        return self.ip


class TargetQueue:
    def __init__(self):
        self._targets: dict[str, ScoredTarget] = {}
        self._completed: dict[str, ScoredTarget] = {}

    def add(self, target: ScoredTarget):
        if target.key not in self._targets:
            self._targets[target.key] = target
        else:
            existing = self._targets[target.key]
            if target.score > existing.score:
                existing.score = target.score
                existing.priority = target.priority

    def add_batch(self, targets: list[ScoredTarget]):
        for t in targets:
            self.add(t)

    def mark_exploited(self, ip: str):
        if ip in self._targets:
            self._targets[ip].exploited = True
            self._targets[ip].vulnerable = True

    def mark_phase_complete(self, ip: str, phase: str):
        if ip in self._targets:
            if phase not in self._targets[ip].completed_phases:
                self._targets[ip].completed_phases.append(phase)

    def pop_highest(self) -> Optional[ScoredTarget]:
        if not self._targets:
            return None
        ordered = sorted(self._targets.values(), key=lambda t: (t.priority.value, -t.score))
        best = ordered[0]
        del self._targets[best.key]
        return best

    def peek_highest(self) -> Optional[ScoredTarget]:
        if not self._targets:
            return None
        ordered = sorted(self._targets.values(), key=lambda t: (t.priority.value, -t.score))
        return ordered[0]

    def complete(self, target: ScoredTarget):
        self._completed[target.key] = target
        self._targets.pop(target.key, None)

    def pending_count(self) -> int:
        return len(self._targets)

    def completed_count(self) -> int:
        return len(self._completed)

    def all_targets(self) -> list[ScoredTarget]:
        return list(self._targets.values()) + list(self._completed.values())

    def reset(self):
        self._targets.clear()
        self._completed.clear()


class TargetScorer:
    @staticmethod
    def score(target: ScoredTarget, findings: list[Finding] = None) -> float:
        score = 0.0
        findings = findings or []

        if target.ports_open:
            score += len(target.ports_open) * 5
        for p in target.ports_open:
            if p in (22, 445, 3389, 5985, 5986, 1433, 3306, 5432):
                score += 15
            elif p == 80 or p == 443:
                score += 8

        if target.os:
            os_lower = target.os.lower()
            if "windows" in os_lower:
                score += 20
            elif "linux" in os_lower:
                score += 10

        if target.domain:
            score += 25

        for f in findings:
            if f.severity == Severity.CRITICAL:
                score += 30
            elif f.severity == Severity.HIGH:
                score += 15
            elif f.severity == Severity.MEDIUM:
                score += 7
            elif f.severity == Severity.LOW:
                score += 3

        priority_weights = {
            TargetPriority.CRITICAL: 100,
            TargetPriority.HIGH: 50,
            TargetPriority.MEDIUM: 25,
            TargetPriority.LOW: 10,
            TargetPriority.INFO: 0,
        }
        score += priority_weights.get(target.priority, 0)

        return score


async def run_multitarget(target: str, findings: list[Finding] = None) -> PhaseResult:
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    queue = TargetQueue()

    candidates = _extract_targets_from_findings(all_findings, target)
    scored = []
    for ip, data in candidates.items():
        st = ScoredTarget(
            ip=ip,
            hostname=data.get("hostname", ""),
            ports_open=data.get("ports", []),
            domain=data.get("domain", ""),
        )
        st.score = TargetScorer.score(st, all_findings)
        if data.get("critical", False):
            st.priority = TargetPriority.CRITICAL
        elif data.get("high", False):
            st.priority = TargetPriority.HIGH
        scored.append(st)

    queue.add_batch(scored)

    for st in scored:
        all_findings.append(Finding(
            phase="multitarget", type="target_scored", target=target,
            host=st.ip, severity=Severity.INFO,
            description=f"Target scored: {st.ip} (score={st.score:.0f}, priority={st.priority.name})",
            evidence=f"ports={st.ports_open} os={st.os} domain={st.domain}",
        ))

    ordered_targets = []
    while True:
        t = queue.pop_highest()
        if t is None:
            break
        ordered_targets.append(t)

    for i, t in enumerate(ordered_targets):
        all_findings.append(Finding(
            phase="multitarget", type="target_queue_order", target=target,
            host=t.ip, severity=Severity.INFO,
            description=f"Priority #{i + 1}: {t.ip} (score={t.score:.0f})",
            evidence=f"priority={t.priority.name} exploited={t.exploited}",
        ))

    latency = time.time() - t0
    return PhaseResult(
        phase="multitarget",
        success=True,
        findings=all_findings,
        summary=f"Multi-target: {len(scored)} targets scored, ordered execution plan ready",
        latency=latency,
        error="; ".join(errors) if errors else None,
    )


def _extract_targets_from_findings(findings: list[Finding], primary: str) -> dict:
    targets: dict[str, dict] = {}
    for f in findings:
        if f.host and f.host != primary:
            if f.host not in targets:
                targets[f.host] = {"ports": [], "hostname": "", "domain": "", "critical": False, "high": False}
            if f.port and f.port not in targets[f.host]["ports"]:
                targets[f.host]["ports"].append(f.port)
            if f.severity == Severity.CRITICAL:
                targets[f.host]["critical"] = True
            if f.severity == Severity.HIGH:
                targets[f.host]["high"] = True
        if f.evidence and not f.host:
            ip = _extract_ip(f.evidence)
            if ip and ip not in targets:
                targets[ip] = {"ports": [], "hostname": "", "domain": "", "critical": False, "high": False}
    return targets


def _extract_ip(text: str) -> Optional[str]:
    import re
    m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    return m.group(1) if m else None