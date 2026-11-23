"""Deduplication and consolidation of scanner output.

Two passes:
1. Exact-fingerprint dedup (same rule, file, line).
2. Same-location collision merge, per source family: when different rules
   from the SAME family fire on the same file+line (e.g. a generic
   credential rule and a specific AWS rule), keep the higher-severity
   finding; ties go to the more specific rule.

   Findings from DIFFERENT families on the same line (e.g. a secrets
   finding and a code-pattern finding) are NOT merged: discarding one
   could hide a distinct problem, and historically this interaction could
   drop a masked secret finding while keeping a less-redacted one. Keep
   the best finding per family per location instead.

   Within the dependency family, the built-in offline demo set and the
   opt-in online OSV lookup often describe the same issue with different
   IDs on the same manifest line; they merge, and ties prefer the OSV
   finding (live data) over the tiny built-in demo entry.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .models import Finding, SEVERITY_ORDER


def _sev_rank(f: Finding) -> int:
    try:
        return SEVERITY_ORDER.index(f.severity)
    except ValueError:
        return 0


def _specificity(f: Finding) -> int:
    return 0 if f.rule_id.startswith("secret.generic") else 1


def _family(f: Finding) -> str:
    # "secrets" | "patterns" | "deps" | "sarif" (from "sarif:<tool>")
    return f.source.split(":", 1)[0]


def deduplicate(findings: List[Finding]) -> Tuple[List[Finding], int]:
    """Return (unique_findings, removed_count)."""
    seen: Dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint(), f)
    exact_removed = len(findings) - len(seen)

    # Group survivors by (file, line, family); keep the winner of each group.
    groups: Dict[Tuple[str, int, str], Finding] = {}
    collision_removed = 0
    for f in seen.values():
        key = (f.file, f.line, _family(f))
        current = groups.get(key)
        if current is None:
            groups[key] = f
            continue
        winner = max(
            (current, f),
            key=lambda x: (
                _sev_rank(x),
                _specificity(x),
                x.confidence == "high",
                x.source == "deps:osv",  # prefer live OSV data over the built-in demo set
            ),
        )
        groups[key] = winner
        collision_removed += 1

    return list(groups.values()), exact_removed + collision_removed
