"""Optional online advisory lookup via OSV (https://osv.dev).

Opt-in (`--osv`): the default pipeline is fully offline against the small
built-in advisory set. With --osv, pinned dependencies are also queried
against the public OSV API (no key required) and results merge into the
same dedup/rank/report pipeline, with source "deps:osv" so they
collision-merge with any built-in finding on the same manifest line.

Uses POST /v1/querybatch so one request covers the whole manifest set.
OSV_BASE_URL can point at a proxy or a local schema-compatible test
server. This module is unit-tested over real HTTP against such a local
stub; it has NOT been exercised against the live api.osv.dev (see
docs/validation.md).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Dict, List, Tuple

from .models import Finding
from .redact import clamp_snippet

DEFAULT_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 1000

# OSV/GHSA database_specific severity labels -> our severity.
_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


class OsvError(Exception):
    """Transport or schema failure talking to OSV."""


def _severity_of(vuln: Dict) -> str:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in _SEV_MAP:
        return _SEV_MAP[label.upper()]
    return "medium"  # conservative default when OSV carries no severity label


def query_osv(deps: List[Tuple[str, str, str, str, int]], base_url: str = None) -> List[Finding]:
    """Query OSV for (ecosystem, name, version, rel_path, lineno) tuples.

    Returns findings only for dependencies OSV reports as vulnerable.
    Raises OsvError on transport/schema failure; callers should warn and
    fall back to the built-in offline set, not crash.
    """
    if not deps:
        return []
    base = (base_url or os.environ.get("OSV_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")

    queries = [
        {"package": {"name": name, "ecosystem": eco}, "version": version}
        for eco, name, version, _path, _line in deps[:MAX_BATCH]
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/v1/querybatch",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OsvError(f"OSV HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise OsvError(f"OSV query failed: {exc}") from exc

    results = data.get("results")
    if not isinstance(results, list) or len(results) < len(queries):
        raise OsvError("OSV response shape unexpected (no aligned results array)")

    findings: List[Finding] = []
    for (eco, name, version, rel_path, lineno), result in zip(deps[:MAX_BATCH], results):
        for vuln in (result or {}).get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id", "unknown"))
            summary = str(vuln.get("summary") or vuln.get("details") or "")[:400]
            severity = _severity_of(vuln)
            findings.append(
                Finding(
                    rule_id=f"dep.osv.{vuln_id.lower()}",
                    title=f"{name} {version} affected by {vuln_id}",
                    severity=severity,
                    confidence="high",
                    file=rel_path,
                    line=lineno,
                    snippet=f"{name}=={version}" if eco == "PyPI" else f'"{name}": "{version}"',
                    description=clamp_snippet(summary, 400) or f"OSV records {vuln_id} affecting this version.",
                    remediation=f"Review {vuln_id} at osv.dev/vulnerability/{vuln_id} and upgrade to a fixed version.",
                    source="deps:osv",
                    cwe=None,
                )
            )
    return findings
