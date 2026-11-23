"""Read-only index over the scanned target tree."""

from __future__ import annotations

from typing import Dict, List, Tuple


class TargetIndex:
    """In-memory view of (relative_path, text) pairs from guards.load_target.

    The index is the ONLY thing investigation actions can see: they cannot
    open new paths, so a finding cannot lead the agent outside the target.
    """

    def __init__(self, contents: List[Tuple[str, str]]):
        self.files: Dict[str, str] = dict(contents)
        self._lines: Dict[str, List[str]] = {
            rel: text.splitlines() for rel, text in contents
        }

    def has_file(self, rel_path: str) -> bool:
        return rel_path in self.files

    def lines(self, rel_path: str) -> List[str]:
        return self._lines[rel_path]

    def all_paths(self) -> List[str]:
        return sorted(self.files)
