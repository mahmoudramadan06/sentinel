"""LLM planner: a model chooses each next investigation action.

The model never touches the filesystem. It receives the redacted finding
and the transcript so far, and must reply with ONE JSON object:
  {"action": "<name>", "args": {...}}   to take an action, or
  {"done": true, "verdict": "<verdict>", "summary": "..."}

The loop validates every field against the action allowlist and the
verdict vocabulary; any violation ends the investigation with a
partial-evidence verdict, so a misbehaving model degrades to safe
deterministic output instead of doing anything.

Loop mechanics (validation, limits, provenance, fallback) are covered by
tests with scripted providers. Planning quality with a real model is NOT
yet validated (no live API calls so far).
"""

from __future__ import annotations

import json
import re
from typing import Dict, List

from ..models import Finding
from ..providers.base import Provider
from .actions import ACTIONS
from .loop import VERDICTS, Done, Planner

_SYSTEM = (
    "You are investigating one security finding in the user's own codebase "
    "by choosing read-only analysis actions. Reply with ONLY one JSON "
    'object: {"action": name, "args": {...}} to gather evidence, or '
    '{"done": true, "verdict": one of ' + ", ".join(sorted(VERDICTS)) +
    ', "summary": one sentence} when the evidence suffices. '
    "Never invent evidence; verdicts must follow from the transcript. "
    "The operator is responsible for running this only on codebases they "
    "are authorized to review."
)


def _menu() -> str:
    return "\n".join(f"- {name}: {desc}" for name, (_fn, desc) in sorted(ACTIONS.items()))


class LLMPlanner(Planner):
    def __init__(self, provider: Provider):
        if provider.is_mock:
            raise ValueError(
                "the mock provider is a deterministic template, not a model; "
                "use the deterministic planner or a real provider"
            )
        self.provider = provider
        self.name = f"llm:{provider.name}"

    def next_action(self, finding: Finding, transcript: List[Dict]):
        user = json.dumps({
            "finding": finding.to_dict(),
            "available_actions": _menu(),
            "transcript": transcript,
        })
        raw = self.provider.complete(_SYSTEM, user)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None  # loop records an invalid-action stop
        try:
            decision = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        if not isinstance(decision, dict):
            return None
        if decision.get("done"):
            return Done(str(decision.get("verdict", "")), str(decision.get("summary", "")))
        return decision
