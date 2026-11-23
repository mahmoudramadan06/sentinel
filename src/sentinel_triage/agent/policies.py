"""Deterministic investigation policies: one decision tree per finding family.

These planners are NOT language models. They encode fixed analyst
playbooks as step sequences over the action allowlist, and their verdicts
follow only from gathered evidence. They run fully offline and are the
default planner.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..models import Finding
from .loop import Done, Planner


def _identifier_from_snippet(finding: Finding) -> Optional[str]:
    m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*=", finding.snippet or "")
    return m.group(1) if m else None


def _package_from_title(finding: Finding) -> Optional[str]:
    m = re.match(r"^([A-Za-z0-9_.\-]+)\s+[0-9]", finding.title or "")
    return m.group(1) if m else None


def _obs(transcript: List[Dict], action: str) -> Optional[Dict]:
    for entry in transcript:
        if entry["action"] == action and entry["ok"]:
            return entry
    return None


class SecretPolicy(Planner):
    """Is this credential a placeholder/example, a fallback with an env
    override, or a likely-live secret?"""

    name = "deterministic:secret"

    def next_action(self, finding: Finding, transcript: List[Dict]) -> object:
        if not transcript:
            return {"action": "classify_credential",
                    "args": {"file": finding.file, "line": finding.line}}

        if _obs(transcript, "classify_credential") and not _obs(transcript, "check_env_usage"):
            ident = _identifier_from_snippet(finding)
            if ident:
                return {"action": "check_env_usage", "args": {"identifier": ident}}
            # No identifier to check: decide on classification alone.
            classification = _obs(transcript, "classify_credential")["observation"]
            return self._decide(classification, None)

        if _obs(transcript, "classify_credential") and _obs(transcript, "check_env_usage"):
            classification = _obs(transcript, "classify_credential")["observation"]
            env_note = _obs(transcript, "check_env_usage")["observation"]
            return self._decide(classification, env_note)

        return Done("needs-human-review", "could not classify the value on the flagged line")

    @staticmethod
    def _decide(classification: str, env_note: Optional[str]) -> Done:
        placeholder = "looks like a placeholder" in classification
        has_env = bool(env_note) and "is also read from the environment" in env_note
        if placeholder:
            return Done("likely-placeholder",
                        "The value matches placeholder/example patterns; rotate only if any real "
                        "system ever used it, and keep dummy values obviously fake.")
        if has_env:
            return Done("possible-env-override",
                        "The value does not look like a placeholder, and the same setting is "
                        "populated from the environment elsewhere - but a hardcoded literal can "
                        "remain in use as a fallback even when an override exists. Treat it as "
                        "live until a deployment proves otherwise, then remove it.")
        return Done("no-mitigating-evidence",
                    "The value does not look like a placeholder and no environment override was "
                    "found in the scanned tree. Absence of evidence is not proof of absence "
                    "(runtime config or other repos may provide one), but treat it as a live "
                    "credential: rotate it and purge it from history.")


class SqlPatternPolicy(Planner):
    """Is the interpolated value guarded in the same file (cast, allowlist,
    validation)? A guard somewhere else in the tree proves nothing about
    this input path, so the search is file-scoped; even an in-file guard
    yields needs-human-review because this planner cannot verify it covers
    the interpolated value."""

    name = "deterministic:sql"

    # Function-call shapes only: bare substrings like "escape" match
    # unrelated words (e.g. an `autoescape=False` setting, which is the
    # opposite of a guard).
    GUARD = (
        r"\bint\(|\bisdigit\(|\ballowlist\b|\bwhitelist\b"
        r"|\b(?:sanitize|escape|validate)[a-z_]*\s*\(|re\.(?:match|fullmatch)\("
    )

    def next_action(self, finding: Finding, transcript: List[Dict]) -> object:
        if not transcript:
            return {"action": "read_context",
                    "args": {"file": finding.file, "line": finding.line, "radius": 15}}
        if not _obs(transcript, "search"):
            return {"action": "search",
                    "args": {"pattern": self.GUARD, "file": finding.file}}
        guards = _obs(transcript, "search")
        guarded = guards["observation"] != "no matches"
        if guarded:
            return Done("needs-human-review",
                        "Guard-like calls exist in the same file, but this planner cannot verify "
                        "they cover the interpolated value on the flagged line; check the input "
                        "path before accepting the finding as mitigated.")
        return Done("unguarded-pattern",
                    "No input validation or escaping calls found in the flagged file. This is "
                    "regex-level evidence, not dataflow: the value may still be constrained "
                    "upstream. Treat the interpolation as injectable until it is parameterized "
                    "or a dataflow check proves the input path safe.")


class DependencyPolicy(Planner):
    """Is the flagged package actually imported?"""

    name = "deterministic:dep"

    def next_action(self, finding: Finding, transcript: List[Dict]) -> object:
        package = _package_from_title(finding)
        if not package:
            return Done("needs-human-review", "could not parse a package name from the finding title")
        if not transcript:
            return {"action": "search_imports", "args": {"package": package}}
        note = _obs(transcript, "search_imports")["observation"]
        if "never imported" in note:
            return Done("no-literal-import",
                        f"No literal import of {package} found in the scanned tree. Dynamic "
                        "imports (importlib, __import__, plugin entry points) and transitive "
                        "use are not ruled out, so reachable-risk is probably lower, not zero; "
                        "still upgrade.")
        return Done("imported-with-advisory",
                    f"{package} is literally imported and an advisory matches the pinned "
                    "version. Reachability of the vulnerable function itself is not "
                    "established; upgrade first, then re-scan.")


class JsSinkPolicy(Planner):
    """Is there a sanitizer in the tree for DOM sinks?"""

    name = "deterministic:js-sink"

    def next_action(self, finding: Finding, transcript: List[Dict]) -> object:
        if not transcript:
            return {"action": "check_mitigation",
                    "args": {"terms": ["DOMPurify", "sanitize(", "sanitizeHtml", "textContent"]}}
        note = _obs(transcript, "check_mitigation")["observation"]
        if "mitigation terms present" in note:
            return Done("needs-human-review",
                        "Sanitizer/safe-sink usage exists somewhere in the tree, but this planner "
                        "cannot verify the flagged assignment passes through it; trace the value "
                        "before accepting the finding as mitigated.")
        return Done("unguarded-pattern",
                    "No sanitizer or safe-sink usage found in the tree. This is regex-level "
                    "evidence, not dataflow; treat user-reachable input to this sink as XSS "
                    "until the value is escaped or traced to a trusted source.")


class GenericPolicy(Planner):
    """Fallback for rule families without a playbook."""

    name = "deterministic:generic"

    def next_action(self, finding: Finding, transcript: List[Dict]) -> object:
        if not transcript:
            return {"action": "read_context",
                    "args": {"file": finding.file, "line": finding.line, "radius": 10}}
        return Done("needs-human-review",
                    "Context gathered; no deterministic playbook exists for this rule family.")


def policy_for(finding: Finding) -> Planner:
    if finding.source == "secrets":
        return SecretPolicy()
    if finding.rule_id.startswith("code.sql"):
        return SqlPatternPolicy()
    if finding.source == "deps" or finding.rule_id.startswith("dep."):
        return DependencyPolicy()
    if finding.rule_id.startswith("code.js"):
        return JsSinkPolicy()
    return GenericPolicy()
