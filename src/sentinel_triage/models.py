"""Core data model for findings and scan results."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Ordered severity scale. Higher is worse.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_SCORE = {name: (i + 1) * 20 for i, name in enumerate(SEVERITY_ORDER)}

# Confidence multiplies the severity score during ranking.
CONFIDENCE_MULTIPLIER = {"low": 0.5, "medium": 0.8, "high": 1.0}


@dataclass(frozen=True)
class Finding:
    """One security finding produced by a scanner.

    `snippet` must already be redacted by the scanner that created the
    finding: it must never contain a full credential or secret value.
    """

    rule_id: str
    title: str
    severity: str  # one of SEVERITY_ORDER
    confidence: str  # low | medium | high
    file: str  # path relative to the scan target
    line: int  # 1-based line number; 0 when not line-specific
    snippet: str
    description: str
    remediation: str
    source: str  # scanner name, e.g. "secrets", "patterns", "deps"
    cwe: Optional[str] = None

    def fingerprint(self) -> str:
        """Stable identity used for deduplication."""
        key = f"{self.rule_id}|{self.file}|{self.line}|{self.title}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def risk_score(self) -> float:
        sev = SEVERITY_SCORE.get(self.severity, SEVERITY_SCORE["info"])
        mult = CONFIDENCE_MULTIPLIER.get(self.confidence, 0.8)
        return round(sev * mult, 2)

    def to_dict(self) -> Dict:
        return {
            "fingerprint": self.fingerprint(),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score(),
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
            "source": self.source,
            "cwe": self.cwe,
        }


@dataclass
class ScanResult:
    """Output of a full scan run."""

    target: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duplicates_removed: int = 0
    baseline_suppressed: int = 0
    warnings: List[str] = field(default_factory=list)
    investigations: Dict[str, Dict] = field(default_factory=dict)  # fingerprint -> investigation
    investigations_planner: str = "none"
    llm_used: bool = False
    llm_provider: str = "none"
    llm_is_mock: bool = False
    # fingerprint -> LLM triage note (rationale / fix guidance)
    triage_notes: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def severity_counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
