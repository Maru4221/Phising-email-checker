from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> int:
        return {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 4}[self]

class Verdict(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"

@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "weight": self.severity.weight,
        }

@dataclass
class ScoreResult:
    verdict: Verdict
    score: int
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
        }

def finding_from_dict(d: Dict[str, Any]) -> Finding:
    return Finding(
        severity=Severity(d.get("severity", "info")),
        title=d.get("title", ""),
        detail=d.get("detail", ""),
        source=d.get("source", "analysis"),
    )

def get_thresholds() -> tuple[int, int]:
    try:
        s = int(os.environ.get("PHISH_SUSPICIOUS_MIN", "3"))
    except ValueError:
        s = 3
    try:
        m = int(os.environ.get("PHISH_MALICIOUS_MIN", "7"))
    except ValueError:
        m = 7
    s = max(1, min(s, 20))
    m = max(s + 1, min(m, 40))
    return s, m

def compute_score(findings: List[Finding]) -> ScoreResult:
    score = sum(f.severity.weight for f in findings)
    suspicious_min, malicious_min = get_thresholds()

    if score >= malicious_min:
        verdict = Verdict.MALICIOUS
    elif score >= suspicious_min:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN

    return ScoreResult(verdict=verdict, score=score, findings=findings)
