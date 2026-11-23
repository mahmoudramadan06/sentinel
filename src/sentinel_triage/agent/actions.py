"""The closed action allowlist for investigations.

Every action:
* is read-only and local (no shell, no writes, no network);
* validates its arguments (unknown file, out-of-range values rejected);
* caps its output;
* passes its output through the secret scrubber, so evidence entering the
  transcript, the report, or an LLM prompt never carries a live secret;
* returns provenance (file:line) for everything it reports.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..redact import clamp_snippet, scrub_text
from .index import TargetIndex

MAX_RADIUS = 40
MAX_MATCHES = 25
MAX_PATTERN_LEN = 120
MAX_OBS_CHARS = 1500
MAX_LINE_MATCH = 1000        # chars of a line fed to the regex engine (worker)
MAX_SEARCH_HARD_SECONDS = 6.0  # subprocess hard timeout: kill on expiry
MAX_WORKER_PAYLOAD = 25 * 1024 * 1024  # serialized lines sent to the worker

# Placeholder assessment: whole curated WORDS with alphabetic boundaries,
# never bare substrings ("chan" would match "merchant", "test" would
# match "contest" - both live-looking values). Structural runs (xxxx,
# 0000, 1111, 1234) are separate evidence.
_PLACEHOLDER_WORDS = (
    "example", "sample", "dummy", "fake", "placeholder", "notreal",
    "changeme", "test", "testing", "your", "todo", "replace",
)
_PLACEHOLDER_WORD_RX = re.compile(
    r"(?<![a-z])(?:" + "|".join(_PLACEHOLDER_WORDS) + r")(?![a-z])")
_PLACEHOLDER_RUN_RX = re.compile(r"x{4,}|0{4,}|1{4,}|1234")


def _unsafe_regex_reason(pattern: str) -> Optional[str]:
    """Reject regex constructs that permit catastrophic backtracking.

    Planner-supplied patterns are untrusted input to a worst-case
    exponential engine: a nested quantifier like (a+)+$ can hang a scan
    for hours on a short line. This static scan rejects backreferences,
    nested quantifiers (a quantified group whose body already contains
    a quantifier) and quantified alternation groups, before compile.
    """
    if re.search(r"\\[1-9]", pattern):
        return "backreferences are not allowed"
    stack: List[Dict[str, bool]] = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":  # skip character class
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "(":
            stack.append({"quant": False, "alt": False})
            if pattern[i + 1:i + 2] == "?":  # group extension: (?: (?= (?! (?P<..
                if pattern[i + 2:i + 3] == "P":
                    end = pattern.find(">", i)
                    i = (end + 1) if end != -1 else n
                else:
                    i += 3
                continue
        elif c == ")" and stack:
            g = stack.pop()
            nxt = pattern[i + 1:i + 2]
            if nxt in ("*", "+", "?", "{"):
                if g["quant"]:
                    return "nested quantifiers can cause catastrophic backtracking"
                if g["alt"]:
                    return "quantified alternation groups are not allowed"
            if stack:  # propagate: the parent body now contains these constructs
                stack[-1]["quant"] = stack[-1]["quant"] or g["quant"]
                stack[-1]["alt"] = stack[-1]["alt"] or g["alt"]
        elif c in "*+?":
            if stack:
                stack[-1]["quant"] = True
        elif c == "{":
            if stack:
                stack[-1]["quant"] = True
            while i < n and pattern[i] != "}":
                i += 1
        elif c == "|":
            if stack:
                stack[-1]["alt"] = True
        i += 1
    return None


@dataclass
class Observation:
    ok: bool
    text: str
    sources: List[str] = field(default_factory=list)

    def clipped(self) -> "Observation":
        return Observation(self.ok, clamp_snippet(self.text, MAX_OBS_CHARS), self.sources[:MAX_MATCHES])


def _reject(reason: str) -> Observation:
    return Observation(False, f"rejected: {reason}", [])


def read_context(index: TargetIndex, file: str, line: int, radius: int = 8) -> Observation:
    """Read +/-radius lines around a location (capped)."""
    if not index.has_file(file):
        return _reject(f"unknown file '{file}'")
    radius = max(1, min(int(radius), MAX_RADIUS))
    lines = index.lines(file)
    line = max(1, min(int(line), len(lines)))
    lo, hi = max(0, line - radius - 1), min(len(lines), line + radius)
    body = "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))
    return Observation(True, scrub_text(body), [f"{file}:{line}"])


def search(index: TargetIndex, pattern: str, max_matches: int = MAX_MATCHES,
           file: str = "") -> Observation:
    """Regex search across the target tree (validated, capped, isolated).

    With `file`, the search is scoped to that one path: scoping is how a
    planner keeps a guard check honest instead of counting keyword hits
    from unrelated files as mitigation evidence.

    The match itself runs in an isolated worker process with a hard
    timeout and kill (see _search_worker.py). That process boundary is
    the runtime bound: the stdlib regex engine backtracks exponentially
    on ambiguous patterns - including group-free shapes no static scan
    can rule out - and no in-process check can interrupt one re.search
    call. The static safety scan below is only a fast-path rejection;
    the kill is the enforcement. A timeout is a clean rejection, so the
    planner sees a failed observation, never a hang.
    """
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        return _reject("pattern missing or too long")
    unsafe = _unsafe_regex_reason(pattern)
    if unsafe:
        return _reject(f"unsafe pattern: {unsafe}")
    try:
        re.compile(pattern)
    except re.error as exc:
        return _reject(f"bad regex: {exc}")
    max_matches = max(1, min(int(max_matches), MAX_MATCHES))
    if file:
        if file not in set(index.all_paths()):
            return _reject("file not in target index")
        paths = [file]
    else:
        paths = list(index.all_paths())
    payload = json.dumps({
        "pattern": pattern,
        "files": {p: list(index.lines(p)) for p in paths},
        "max_matches": max_matches,
    })
    if len(payload) > MAX_WORKER_PAYLOAD:
        return _reject("target too large for isolated search")
    worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_search_worker.py")
    try:
        proc = subprocess.run(
            [sys.executable, worker],
            input=payload.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=MAX_SEARCH_HARD_SECONDS,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run has already killed and reaped the worker.
        return _reject("search exceeded the hard time budget and was killed")
    if proc.returncode != 0:
        return _reject("search worker failed")
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError:
        return _reject("search worker returned unparseable output")
    if data.get("error"):
        return _reject(f"bad regex: {data['error']}")
    hits = [str(h) for h in data.get("hits", [])][:max_matches]
    text = "\n".join(hits)
    if data.get("truncated"):
        text += "\n[truncated: scan budget]"
    if not hits:
        return Observation(True, "no matches", [])
    sources = [h.split(":", 2)[0] + ":" + h.split(":", 2)[1] for h in hits]
    return Observation(True, scrub_text(text), sources).clipped()


def search_usages(index: TargetIndex, identifier: str) -> Observation:
    """Where an identifier is used, and whether use sites look like network calls."""
    if not identifier or not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", identifier):
        return _reject("not a plausible identifier")
    obs = search(index, rf"\b{re.escape(identifier)}\b")
    if not obs.ok or obs.text == "no matches":
        return Observation(True, f"no usages of {identifier}", [])
    networkish = re.compile(r"requests\.|urllib|httpx|fetch\(|axios|socket|curl", re.IGNORECASE)
    flagged = [s for s in obs.text.splitlines() if networkish.search(s)]
    note = f"{len(obs.sources)} usage(s) of {identifier}"
    if flagged:
        note += f"; {len(flagged)} near network-call code"
    return Observation(True, note + "\n" + obs.text, obs.sources).clipped()


def check_env_usage(index: TargetIndex, identifier: str) -> Observation:
    """Whether the same identifier is ALSO populated from the environment
    (suggesting a committed literal is a fallback, not the real value)."""
    if not identifier or not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,48}$", identifier):
        return _reject("not a plausible identifier")
    # One compact pattern: the generic search action caps pattern length,
    # and a six-alternative alternation would exceed it.
    combined = (
        rf"(?:os\.environ(?:\.get)?|os\.getenv|process\.env)[(\[.][\"'\s]{{0,2}}{identifier}\b"
        rf"|\${{{identifier}}}"
    )
    obs = search(index, combined)
    found = obs.ok and obs.text != "no matches"
    note = (f"{identifier} is also read from the environment"
            if found else f"{identifier} is not read from the environment anywhere")
    return Observation(True, note, obs.sources if found else [])


def classify_credential(index: TargetIndex, file: str, line: int) -> Observation:
    """Assess a credential-looking value WITHOUT revealing it.

    Answers: does it look like a placeholder/example, and how long is it?
    The value itself never appears in the observation.
    """
    if not index.has_file(file):
        return _reject(f"unknown file '{file}'")
    lines = index.lines(file)
    if not (1 <= int(line) <= len(lines)):
        return _reject("line out of range")
    text = lines[int(line) - 1]
    m = re.search(r"['\"]([^'\"\s]{8,})['\"]", text)
    if not m:
        return Observation(True, "no string literal on this line to classify", [f"{file}:{line}"])
    value = m.group(1)
    lowered = value.lower()
    hits = sorted(set(_PLACEHOLDER_WORD_RX.findall(lowered)))
    runs = sorted(set(r.lower() for r in _PLACEHOLDER_RUN_RX.findall(lowered)))
    looks_placeholder = bool(hits or runs)
    matched = ", ".join(hits + ["run:" + r for r in runs])
    note = (
        f"value looks like a placeholder/example (matched: {matched})"
        if looks_placeholder
        else "value does NOT look like a placeholder; treat as a live credential"
    )
    return Observation(True, f"{note}; length {len(value)}", [f"{file}:{line}"])


def search_imports(index: TargetIndex, package: str) -> Observation:
    """Whether a dependency is actually imported anywhere in the tree."""
    if not package or not re.match(r"^[A-Za-z0-9_.\-]{1,64}$", package):
        return _reject("not a plausible package name")
    mod = package.lower().replace("-", "_")
    obs = search(index, rf"^\s*(import|from)\s+{re.escape(mod)}\b|require\(['\"]{re.escape(package)}['\"]\)|from ['\"]{re.escape(package)}['\"]")
    found = obs.ok and obs.text != "no matches"
    note = (f"{package} is imported at {len(obs.sources)} location(s)"
            if found else f"{package} is never imported in the scanned tree")
    return Observation(True, note, obs.sources if found else [])


def check_mitigation(index: TargetIndex, terms: List[str]) -> Observation:
    """Whether any of the given mitigation terms (e.g. sanitizer names)
    appear in the tree."""
    if not terms or not all(isinstance(t, str) and 0 < len(t) <= 40 for t in terms):
        return _reject("bad terms")
    rx = "|".join(re.escape(t) for t in terms)
    obs = search(index, rx)
    found = obs.ok and obs.text != "no matches"
    note = ("mitigation terms present" if found else "no mitigation terms found")
    return Observation(True, f"{note}: {', '.join(terms)}", obs.sources if found else [])


# name -> (function, human description for prompts/docs)
ACTIONS: Dict[str, tuple] = {
    "read_context": (read_context, "read +/-radius lines around file:line"),
    "search": (search, "regex search across the target tree (optional 'file' scopes to one path)"),
    "search_usages": (search_usages, "where an identifier is used; flags network-call proximity"),
    "check_env_usage": (check_env_usage, "whether an identifier is also populated from env vars"),
    "classify_credential": (classify_credential, "placeholder assessment of a credential value without revealing it"),
    "search_imports": (search_imports, "whether a dependency is imported anywhere"),
    "check_mitigation": (check_mitigation, "whether mitigation terms (e.g. DOMPurify, sanitize) appear"),
}


class ActionError(Exception):
    pass


def run_action(index: TargetIndex, name: str, args: dict) -> Observation:
    """Validate and execute one action from the allowlist."""
    fn = ACTIONS.get(name)
    if fn is None:
        raise ActionError(f"unknown action '{name}'; allowed: {', '.join(sorted(ACTIONS))}")
    if not isinstance(args, dict):
        raise ActionError("action args must be an object")
    try:
        return fn[0](index, **args).clipped()
    except (TypeError, ValueError) as exc:
        raise ActionError(f"bad args for '{name}': {exc}") from exc
