from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}


@dataclass
class Threat:
    analyzer: str
    type: str
    title: str
    description: str
    severity: Severity
    location: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    apk_path: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    findings: List[Threat] = field(default_factory=list)

    def add(self, threat: Threat) -> None:
        self.findings.append(threat)

    def extend(self, threats: List[Threat]) -> None:
        self.findings.extend(threats)

    # ---------- RISK SCORING ----------

    def severity_stats(self) -> Dict[Severity, int]:
        stats: Dict[Severity, int] = {s: 0 for s in Severity}
        for t in self.findings:
            stats[t.severity] = stats.get(t.severity, 0) + 1
        return stats

    def risk_score(self) -> int:
        score = 0
        for t in self.findings:
            score += SEVERITY_WEIGHTS.get(t.severity, 0)
        return score

    def risk_grade(self) -> str:
        """
        Грубая шкала:
        0–10:   A (низкий риск)
        11–30:  B
        31–60:  C
        61–100: D
        >100:   E (очень высокий риск)
        """
        score = self.risk_score()
        if score <= 10:
            return "A"
        if score <= 30:
            return "B"
        if score <= 60:
            return "C"
        if score <= 100:
            return "D"
        return "E"
