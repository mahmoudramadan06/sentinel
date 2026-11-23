"""Penetration Testing Tree (PTT) core, forked from PentestGPT.

Upstream: https://github.com/GreyDGL/PentestGPT (MIT License,
Copyright (c) 2023 Grey_D). See THIRD_PARTY_NOTICES.md and the
LICENSE text under third_party/pentestgpt/.

What this fork keeps:
    * The PTT concept and text format: a layered task tree (1, 1.1, 1.1.1)
      where every task carries a status of to-do / completed /
      not-applicable.

What this fork changes (substantively):
    * Upstream shipped the PTT only as LLM prompt text plus an interactive
      REPL. Here the tree is a real, tested data model with a strict parser
      and renderer, so it can be generated, validated and diffed without an
      LLM.
    * Upstream's prompt text asserted the tester holds "valid certificates
      and approval" for a "certified experiment". Those blanket claims are
      removed: authorization here comes from a machine-checked scope file
      (sentinel_triage.scope), and prompts state the scope that was actually
      loaded instead of claiming approvals nobody verified.
    * Task creation is scope-gated: a task carrying a target outside the
      loaded scope is refused, in code.
    * A deterministic offline planner provides the default reasoning pass,
      so the tree is useful with no API key and no spend. An optional LLM
      pass goes through sentinel_triage.providers like the rest of the
      package.

Intentional non-goals (differing from upstream's direction): no exploit
chains, no post-exploitation task generation, no autonomous command
execution. This module plans and records authorized reconnaissance work.
"""

from .model import PTTNode, STATUS_TODO, STATUS_DONE, STATUS_NA, parse_ptt, render_ptt
from .planner import build_initial_tree, expand_recon_task, ScopeGateError

__all__ = [
    "PTTNode",
    "STATUS_TODO",
    "STATUS_DONE",
    "STATUS_NA",
    "parse_ptt",
    "render_ptt",
    "build_initial_tree",
    "expand_recon_task",
    "ScopeGateError",
]
