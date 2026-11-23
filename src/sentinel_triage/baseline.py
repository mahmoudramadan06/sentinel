"""Baseline support: suppress findings a human has already reviewed.

A baseline file is a small JSON document the user writes after reviewing a
report, listing the fingerprints of accepted / won't-fix findings:

    {"suppressed": ["0123abcd...", "ef014567..."]}

Default location: .sentinel-baseline.json at the root of the scan target.
Suppressions are counted and disclosed in report metadata, never silent.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional, Set, Tuple

from .models import Finding

DEFAULT_BASELINE_NAME = ".sentinel-baseline.json"


def load_baseline(target: str, baseline_path: Optional[str] = None) -> Set[str]:
    """Return the set of suppressed fingerprints. Missing file = empty set."""
    path = baseline_path or os.path.join(target, DEFAULT_BASELINE_NAME)
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline file {path}: {exc}") from exc
    suppressed = data.get("suppressed", [])
    if not isinstance(suppressed, list):
        raise ValueError(f"baseline file {path}: 'suppressed' must be a list")
    return {str(fp) for fp in suppressed}


def apply_baseline(findings: List[Finding], suppressed: Set[str]) -> Tuple[List[Finding], int]:
    """Split off suppressed findings. Returns (kept, suppressed_count)."""
    if not suppressed:
        return findings, 0
    kept = [f for f in findings if f.fingerprint() not in suppressed]
    return kept, len(findings) - len(kept)
