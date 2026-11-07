"""Data models and security grading logic for mcp-shield."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
        }[self]


@dataclass
class Finding:
    """Represents a single security issue discovered during a scan."""

    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    target: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanResult:
    """Aggregated scan results and calculated security scorecard."""

    scanned_targets: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Calculate a 0-100 security score based on finding severities."""
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Map numerical score and critical findings to a letter grade (A-F)."""
        s = self.score
        has_critical = any(f.severity == Severity.CRITICAL for f in self.findings)
        if s >= 95 and not has_critical:
            return "A"
        if s >= 80 and not has_critical:
            return "B"
        if s >= 65:
            return "C"
        if s >= 45:
            return "D"
        return "F"

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "scanned_targets": self.scanned_targets,
            "counts": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
