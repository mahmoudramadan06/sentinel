"""Hardcoded-secret scanner.

Every match is redacted in the finding snippet before it leaves this module:
the report and any LLM prompt only ever see masked values. (The pipeline
additionally scrubs every finding centrally at the boundary; this module's
own masking is the first of two layers.)
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..models import Finding
from ..redact import clamp_snippet, mask_line, secret_patterns

_RULE_META = None


def _rule_meta() -> List[dict]:
    import json
    import os
    global _RULE_META
    if _RULE_META is None:
        path = os.path.join(os.path.dirname(__file__), "..", "rules", "secrets.json")
        with open(path, "r", encoding="utf-8") as fh:
            _RULE_META = json.load(fh)
    return _RULE_META


def scan_secrets(files: List[Tuple[str, str]]) -> List[Finding]:
    """Scan (relative_path, text) pairs for hardcoded secrets."""
    findings: List[Finding] = []
    rules = [(r, re.compile(r["pattern"])) for r in _rule_meta()]
    for rel_path, text in files:
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule, rx in rules:
                m = rx.search(line)
                if not m:
                    continue
                snippet = clamp_snippet(mask_line(line, m.start(), m.end()))
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        file=rel_path,
                        line=lineno,
                        snippet=snippet,
                        description=rule["description"],
                        remediation=rule["remediation"],
                        source="secrets",
                        cwe=rule.get("cwe"),
                    )
                )
    return findings
