"""Prompt text for the optional LLM refinement pass.

Forked and adapted from PentestGPT (MIT). The upstream prompts asserted the
tester holds "valid certificates and approval" for a "certified experiment".
Those claims are removed here: the prompt states the scope that was actually
loaded and machine-checked, and constrains the model to reconnaissance
planning. Output still passes planner.gate_llm_revision before use, so the
prompt is advisory text, not the enforcement point.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopeRefinementPrompt:
    """Prompts for refining a PTT within a loaded scope."""

    scope_summary: str

    @property
    def system(self) -> str:
        return (
            "You are assisting with reconnaissance planning for a security "
            "engagement whose authorized scope has been machine-checked.\n"
            f"Loaded scope:\n{self.scope_summary}\n\n"
            "Rules:\n"
            "1. Only reconnaissance tasks: passive OSINT, enumeration, "
            "fingerprinting, bounded crawling, safe service detection.\n"
            "2. Never propose exploitation, brute force, credential attacks, "
            "persistence, evasion, or post-exploitation tasks.\n"
            "3. Never reference targets outside the loaded scope.\n"
            "4. Keep the Penetration Testing Tree format: layered numbers "
            "(1, 1.1, 1.1.1) with statuses to-do / completed / "
            "not applicable.\n"
            "5. Your output will be machine-validated against the scope; "
            "out-of-scope content is discarded."
        )

    @property
    def revise_tree(self) -> str:
        return (
            "Revise the following task tree using the test results provided. "
            "Add to-do tasks only for discoveries inside the scope, mark "
            "finished work completed, and remove outdated tasks.\n\n"
        )
