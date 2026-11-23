"""Importers for external scanner output.

SARIF (Static Analysis Results Interchange Format, OASIS standard) is the
common output of Semgrep, CodeQL, Trivy, and many others. Importing it
lets sentinel-triage do its real job on real-world scanner noise:
deduplicate, rank, and explain findings it did not produce itself.

Imported files are untrusted input. This module therefore:
* rejects malformed or non-SARIF JSON with a clean error, never a traceback;
* caps field lengths and result counts;
* runs the secrets scanner's patterns over every imported text field and
  masks matches, because real scanner output regularly embeds the secret
  it found, and that secret must never reach a report or an LLM prompt.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from .models import Finding
from .redact import clamp_snippet, scrub_text, secret_patterns

MAX_SARIF_RESULTS = 50_000
MAX_SARIF_BYTES = 50_000_000


class SarifImportError(ValueError):
    """Raised when a SARIF file cannot be imported. Carries a clean message."""


# SARIF level -> our severity. SARIF levels say nothing about business
# impact, so the mapping is deliberately conservative.
LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def redact_text(text: str, patterns: List[re.Pattern]) -> str:
    """Mask any secret-pattern matches inside untrusted imported text.

    Thin wrapper kept for readability at call sites; the implementation
    lives in redact.scrub_text, the same code the pipeline boundary uses.
    """
    return scrub_text(text, patterns)


def _text(container, key):
    """Safely read a {'text': ...} child from possibly-malformed SARIF."""
    if not isinstance(container, dict):
        return None
    v = container.get(key)
    if isinstance(v, dict):
        v = v.get("text")
    return v if isinstance(v, str) else None


def import_sarif(path: str) -> List[Finding]:
    """Import findings from a SARIF 2.x file. Raises SarifImportError on bad input."""
    try:
        if os.path.getsize(path) > MAX_SARIF_BYTES:
            raise SarifImportError(f"{path}: file too large (> {MAX_SARIF_BYTES} bytes)")
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except SarifImportError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise SarifImportError(f"{path}: cannot read file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SarifImportError(f"{path}: not valid JSON: {exc}") from exc

    if not isinstance(doc, dict) or not str(doc.get("version", "")).startswith("2."):
        raise SarifImportError(f"{path}: not a SARIF 2.x document")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise SarifImportError(f"{path}: SARIF document has no 'runs' array")

    patterns = secret_patterns()
    findings: List[Finding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = (run.get("tool", {}).get("driver", {}) or {}).get("name", "unknown")
        rules: Dict[str, dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            if isinstance(rule, dict):
                rules[rule.get("id", "")] = rule

        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        if len(results) > MAX_SARIF_RESULTS:
            results = results[:MAX_SARIF_RESULTS]

        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId", "unknown-rule"))
            rule = rules.get(rule_id, {})
            level = str(result.get("level", "warning"))
            severity = LEVEL_TO_SEVERITY.get(level, "medium")

            locations = result.get("locations") or [{}]
            location = {}
            if isinstance(locations[0], dict):
                location = locations[0].get("physicalLocation") or {}
            if not isinstance(location, dict):
                location = {}
            artifact = location.get("artifactLocation")
            uri = str(artifact.get("uri", "unknown")) if isinstance(artifact, dict) else "unknown"
            region = location.get("region")
            region = region if isinstance(region, dict) else {}
            try:
                line = int(region.get("startLine", 0))
            except (TypeError, ValueError):
                line = 0
            snippet = _text(region, "snippet") or _text(result, "message") or ""

            title = _text(rule, "shortDescription") or rule.get("name") or rule_id
            description = _text(rule, "fullDescription") or _text(result, "message") or title
            remediation = _text(rule, "help") or (
                "Review the finding against the rule documentation for "
                f"{tool} rule '{rule_id}'."
            )

            findings.append(
                Finding(
                    rule_id=f"sarif.{tool}.{rule_id}",
                    title=redact_text(str(title), patterns),
                    severity=severity,
                    confidence="medium",
                    file=uri,
                    line=line,
                    snippet=clamp_snippet(redact_text(str(snippet), patterns)),
                    description=clamp_snippet(redact_text(str(description), patterns), 400),
                    remediation=clamp_snippet(redact_text(str(remediation), patterns), 400),
                    source=f"sarif:{tool}",
                    cwe=None,
                )
            )
    return findings
