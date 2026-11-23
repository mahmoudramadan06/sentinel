"""Bounded investigation loop: the agentic core of sentinel-triage.

An investigation takes ONE finding and tries to answer a concrete triage
question about it ("is this credential a placeholder?", "is this SQL
interpolation guarded?", "is this dependency even imported?") by choosing
actions from a closed allowlist of read-only local analysis primitives,
inspecting the results, and iterating until it reaches a verdict or hits
a hard limit. Every observation carries provenance (file:line), every
observation passes the secret scrubber, and the full transcript is
recorded for review.

Two planners drive the same loop with the same limits and provenance:
* deterministic (default, offline): fixed decision trees per finding
  family. Fully tested.
* llm (optional): a model picks each next action as structured JSON; the
  loop validates every action against the allowlist and falls back to a
  deterministic verdict on any violation. Loop mechanics are tested with
  scripted planners; live-model planning is NOT yet validated.

The action space contains no shell, no writes, and no network.
"""

from .loop import Investigation, Limits, investigate
from .index import TargetIndex

__all__ = ["Investigation", "Limits", "investigate", "TargetIndex"]
