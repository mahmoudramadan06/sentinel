"""Deterministic risk ranking."""

from __future__ import annotations

from typing import List

from .models import Finding, SEVERITY_ORDER


def rank_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings by risk score, then severity, then location.

    Fully deterministic: identical input always yields identical order,
    which is what makes the offline pipeline testable and reviewable.
    """

    def key(f: Finding):
        return (-f.risk_score(), -SEVERITY_ORDER.index(f.severity), f.file, f.line, f.rule_id)

    return sorted(findings, key=key)
