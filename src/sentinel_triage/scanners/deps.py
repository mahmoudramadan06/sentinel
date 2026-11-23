"""Dependency manifest scanner with a small built-in offline advisory set.

Parses requirements.txt and package.json and compares pinned versions
against data/advisories.json. The built-in set is deliberately small and
documented as such; it demonstrates the pipeline, it is not a CVE feed.

requirements.txt handling notes:
* Extras are parsed and dropped for the lookup (requests[security]==2.19.0
  is checked as requests 2.19.0), never silently ignored.
* Trailing inline comments are stripped.
* Only requirements with a resolvable version are checked; unpinned or
  unparseable lines are skipped (they carry no version to compare).
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Tuple

from ..models import Finding

_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "advisories.json")

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)"      # package name
    r"(\[[^\]]*\])?"               # optional extras, e.g. [security]
    r"\s*(==|~=|>=|<=|>|<)?"       # optional operator
    r"\s*([A-Za-z0-9_.*+\-]+)?"    # optional version
)


def _load_advisories() -> Dict:
    with open(_DATA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_version(text: str) -> Tuple[int, ...]:
    """Parse '1.26.3rc1' into a comparable tuple of ints (suffixes dropped)."""
    parts = []
    for chunk in re.split(r"[.\-+_]", text.strip().lstrip("v")):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group(0)) if m else 0)
    return tuple(parts)


def version_lt(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a < b


def _advisory_findings(ecosystem: str, name: str, version: str, rel_path: str,
                       lineno: int, advisories: Dict) -> List[Finding]:
    findings: List[Finding] = []
    for adv in advisories.get(ecosystem, {}).get(name.lower(), []):
        if version_lt(parse_version(version), parse_version(adv["affected_below"])):
            findings.append(
                Finding(
                    rule_id=f"dep.{ecosystem}.{adv['id'].lower()}",
                    title=f"{name} {version} affected by {adv['id']}",
                    severity=adv["severity"],
                    confidence="high",
                    file=rel_path,
                    line=lineno,
                    snippet=f"{name}=={version}" if ecosystem == "pypi" else f'"{name}": "{version}"',
                    description=adv["summary"],
                    remediation=adv["fix"],
                    source="deps",
                    cwe=None,
                )
            )
    return findings


def _scan_requirements(text: str, rel_path: str, advisories: Dict) -> List[Finding]:
    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = re.sub(r"\s+#.*$", "", line).strip()  # drop inline comments
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = _REQ_LINE.match(stripped)
        if not m or not m.group(4):
            continue
        findings.extend(_advisory_findings("pypi", m.group(1), m.group(4), rel_path, lineno, advisories))
    return findings


def _scan_package_json(text: str, rel_path: str, advisories: Dict) -> List[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    findings: List[Finding] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            cleaned = re.sub(r"^[\^~>=<\s]+", "", str(spec))
            if not cleaned or not re.match(r"^\d", cleaned):
                continue
            findings.extend(_advisory_findings("npm", name, cleaned, rel_path, 0, advisories))
    return findings


def iter_dependencies(files: List[Tuple[str, str]]):
    """Yield (ecosystem, name, version, rel_path, lineno) for every pinned
    dependency in every manifest. Shared by the built-in offline checker
    and the optional online OSV lookup, so both see the same parse."""
    for rel_path, text in files:
        base = os.path.basename(rel_path).lower()
        if base in ("requirements.txt",) or base.startswith("requirements-"):
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = re.sub(r"\s+#.*$", "", line).strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                    continue
                m = _REQ_LINE.match(stripped)
                if m and m.group(4):
                    yield "PyPI", m.group(1), m.group(4), rel_path, lineno
        elif base == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies"):
                for name, spec in (data.get(section) or {}).items():
                    cleaned = re.sub(r"^[\^~>=<\s]+", "", str(spec))
                    if cleaned and re.match(r"^\d", cleaned):
                        yield "npm", name, cleaned, rel_path, 0


def scan_dependencies(files: List[Tuple[str, str]]) -> List[Finding]:
    """Scan (relative_path, text) pairs against the built-in offline set."""
    advisories = _load_advisories()
    findings: List[Finding] = []
    eco_key = {"PyPI": "pypi", "npm": "npm"}
    for ecosystem, name, version, rel_path, lineno in iter_dependencies(files):
        findings.extend(_advisory_findings(eco_key[ecosystem], name, version, rel_path, lineno, advisories))
    return findings
