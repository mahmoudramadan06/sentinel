"""Dangerous-code-pattern scanner (lightweight, regex-based).

This is a first-pass noise reducer, not a replacement for a real SAST
engine like Semgrep. Rules are intentionally conservative: they flag
well-known dangerous idioms and mark confidence honestly.

Snippets are raw source lines; any secret content in them is masked by
the pipeline's central boundary scrub, so this module never needs to be
trusted with redaction on its own.
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from ..models import Finding
from ..redact import clamp_snippet

_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "patterns.json")


def _load_rules() -> List[dict]:
    with open(_RULES_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def scan_code_patterns(files: List[Tuple[str, str]]) -> List[Finding]:
    """Scan (relative_path, text) pairs for dangerous code patterns."""
    findings: List[Finding] = []
    rules = [(r, re.compile(r["pattern"])) for r in _load_rules()]
    for rel_path, text in files:
        ext = os.path.splitext(rel_path)[1].lower()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule, rx in rules:
                if ext not in rule.get("extensions", []):
                    continue
                if rx.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule["id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            file=rel_path,
                            line=lineno,
                            snippet=clamp_snippet(line),
                            description=rule["description"],
                            remediation=rule["remediation"],
                            source="patterns",
                            cwe=rule.get("cwe"),
                        )
                    )
    return findings
