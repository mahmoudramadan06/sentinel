"""The investigation loop.

A planner proposes the next action; the loop validates it against the
allowlist, executes it read-only, appends the observation to the
transcript, and repeats until the planner returns a verdict or a hard
limit is hit. The loop owns the limits and the provenance, so no planner
(deterministic or LLM) can exceed them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import Finding
from ..redact import clamp_snippet, sanitize_markdown, scrub_text
from .actions import ActionError, run_action
from .index import TargetIndex

MAX_SUMMARY_CHARS = 600
MAX_ARG_CHARS = 160
MAX_STORED_ARGS = 10


def _safe_text(text: str, limit: int = MAX_SUMMARY_CHARS) -> str:
    """The boundary for untrusted strings entering a report: mask secret
    patterns, neutralize active markup (images/links/HTML/backticks),
    then clamp length. Applied to planner-returned summaries and to
    every observation before it reaches the transcript or evidence, so
    no planner or target file can inject markup or bloat a report."""
    return clamp_snippet(sanitize_markdown(scrub_text(text or "")), limit)


def _safe_args(args: object) -> Dict:
    """Bounded copy of planner-supplied args for the transcript."""
    if not isinstance(args, dict):
        return {}
    out = {}
    for k, v in list(args.items())[:MAX_STORED_ARGS]:
        out[str(k)[:40]] = clamp_snippet(v, MAX_ARG_CHARS) if isinstance(v, str) else v
    return out

# Evidence-qualified heuristic labels: each names what was actually
# observed, not a conclusion about exploitability. The deterministic
# planners never perform dataflow, so labels that would assert
# confirmed risk or verified mitigation are deliberately absent.
VERDICTS = {
    "likely-placeholder",
    "possible-env-override",
    "no-mitigating-evidence",
    "unguarded-pattern",
    "imported-with-advisory",
    "no-literal-import",
    "needs-human-review",
    "partial-evidence",
}


@dataclass
class Limits:
    max_steps: int = 8
    max_transcript_chars: int = 6000


@dataclass
class Investigation:
    fingerprint: str
    verdict: str
    planner: str
    summary: str
    evidence: List[Dict] = field(default_factory=list)  # [{note, sources}]
    steps: int = 0
    stopped_by: str = "policy-done"  # policy-done | step-limit | planner-error | invalid-action
    transcript: List[Dict] = field(default_factory=list)  # [{step, action, args, ok, observation}]

    def to_dict(self) -> Dict:
        return {
            "fingerprint": self.fingerprint,
            "verdict": self.verdict,
            "planner": self.planner,
            "summary": self.summary,
            "evidence": self.evidence,
            "steps": self.steps,
            "stopped_by": self.stopped_by,
            "transcript": self.transcript,
        }


class Done:
    """Planner signal: investigation complete."""

    def __init__(self, verdict: str, summary: str):
        if verdict not in VERDICTS:
            verdict = "needs-human-review"
        self.verdict = verdict
        self.summary = summary


class Planner:
    """Interface: given the finding and the transcript so far, return the
    next {"action": name, "args": {...}} or a Done."""

    name = "base"

    def next_action(self, finding: Finding, transcript: List[Dict]):
        raise NotImplementedError


def investigate(finding: Finding, index: TargetIndex, planner: Planner,
                limits: Optional[Limits] = None) -> Investigation:
    limits = limits or Limits()
    inv = Investigation(
        fingerprint=finding.fingerprint(),
        verdict="needs-human-review",
        planner=planner.name,
        summary="",
    )
    transcript_chars = 0

    for step in range(1, limits.max_steps + 1):
        try:
            decision = planner.next_action(finding, inv.transcript)
        except Exception as exc:  # planner failures must not crash a scan
            inv.stopped_by = "planner-error"
            inv.verdict = "partial-evidence"
            inv.summary = _safe_text(f"planner failed at step {step}: {exc}")
            break

        if isinstance(decision, Done):
            inv.verdict = decision.verdict
            inv.summary = _safe_text(decision.summary)
            inv.stopped_by = "policy-done"
            break

        if not isinstance(decision, dict) or "action" not in decision:
            inv.stopped_by = "invalid-action"
            inv.verdict = "partial-evidence"
            inv.summary = f"planner returned an unparseable decision at step {step}"
            break

        action_name = decision.get("action")
        args = decision.get("args", {})
        try:
            obs = run_action(index, action_name, args)
        except ActionError as exc:
            inv.stopped_by = "invalid-action"
            inv.verdict = "partial-evidence"
            inv.summary = _safe_text(f"step {step}: {exc}")
            inv.transcript.append({
                "step": step, "action": str(action_name)[:60], "args": _safe_args(args),
                "ok": False, "observation": _safe_text(str(exc), 300),
            })
            break

        entry = {
            "step": step,
            "action": action_name,
            "args": _safe_args(args),
            "ok": obs.ok,
            "observation": _safe_text(obs.text),
        }
        transcript_chars += len(obs.text)
        if transcript_chars > limits.max_transcript_chars:
            inv.stopped_by = "step-limit"
            inv.verdict = "partial-evidence"
            inv.summary = "transcript budget exhausted"
            break
        inv.transcript.append(entry)
        inv.evidence.append({
            "note": _safe_text(obs.text, 300),
            "sources": [str(s)[:200] for s in obs.sources],
            "via": action_name,
        })
    else:
        inv.stopped_by = "step-limit"
        inv.verdict = "partial-evidence"
        inv.summary = f"no verdict within {limits.max_steps} steps"

    inv.steps = len(inv.transcript)
    return inv
