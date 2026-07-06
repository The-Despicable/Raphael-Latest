from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import time


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    phase: str
    type: str
    target: str
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    cve: Optional[str] = None
    payload: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "type": self.type,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "cve": self.cve,
            "raw": self.raw,
        }


@dataclass
class PhaseResult:
    phase: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    raw_output: str = ""
    latency: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "raw_output": self.raw_output[:2000] if self.raw_output else "",
            "latency": round(self.latency, 2),
            "error": self.error,
        }
