"""PTT data model: strict parser and renderer for the PentestGPT tree format.

Forked concept from PentestGPT (MIT); this implementation is original to
sentinel and covered by sentinel's own tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

STATUS_TODO = "to-do"
STATUS_DONE = "completed"
STATUS_NA = "not applicable"

_STATUSES = (STATUS_TODO, STATUS_DONE, STATUS_NA)

_LINE = re.compile(
    r"^(?P<indent>\s*)(?P<num>\d+(?:\.\d+)*)\.?\s+(?P<title>.*?)\s*"
    r"(?:[-–]\s*[\(\[]?(?P<status>to-do|completed|not applicable)[\)\]]?)?$"
)


class PTTParseError(ValueError):
    pass


@dataclass
class PTTNode:
    number: str
    title: str
    status: str = STATUS_TODO
    target: str = ""           # optional host/IP this task acts on
    children: list = field(default_factory=list)

    def add(self, title: str, status: str = STATUS_TODO, target: str = "") -> "PTTNode":
        if status not in _STATUSES:
            raise PTTParseError(f"unknown status {status!r}")
        child = PTTNode(
            number=f"{self.number}.{len(self.children) + 1}",
            title=title,
            status=status,
            target=target,
        )
        self.children.append(child)
        return child

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def find(self, number: str) -> "PTTNode":
        for node in self.walk():
            if node.number == number:
                return node
        raise KeyError(number)

    def todo_leaves(self):
        return [n for n in self.walk() if n.status == STATUS_TODO and not n.children]


def render_ptt(root: PTTNode) -> str:
    lines = []

    def _emit(node: PTTNode, depth: int) -> None:
        lines.append(
            f"{'    ' * depth}{node.number}. {node.title} - ({node.status})"
        )
        for child in node.children:
            _emit(child, depth + 1)

    _emit(root, 0)
    return "\n".join(lines) + "\n"


def parse_ptt(text: str) -> PTTNode:
    """Parse the PTT text format into a tree.

    Strict about numbering: every node number must be its parent's number
    plus one more component, and siblings must be sequential. A malformed
    tree raises PTTParseError instead of being silently reshaped.
    """
    root = None
    last_at_depth: dict = {}
    parent_of: dict = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        match = _LINE.match(raw)
        if not match:
            raise PTTParseError(f"line {lineno}: not a PTT line: {raw!r}")
        number = match.group("num")
        title = match.group("title").strip().rstrip("-– ").strip()
        status = match.group("status") or STATUS_TODO
        parts = number.split(".")
        depth = len(parts) - 1
        node = PTTNode(number=number, title=title, status=status)
        if depth == 0:
            if root is not None:
                raise PTTParseError("multiple root tasks are not supported")
            if number != "1":
                raise PTTParseError(f"root task must be numbered 1, got {number}")
            root = node
        else:
            parent_number = ".".join(parts[:-1])
            parent = last_at_depth.get(parent_number) or parent_of.get(parent_number)
            if parent is None:
                raise PTTParseError(f"line {lineno}: no parent {parent_number} for {number}")
            expected = f"{parent_number}.{len(parent.children) + 1}"
            if number != expected:
                raise PTTParseError(
                    f"line {lineno}: expected task number {expected}, got {number}"
                )
            parent.children.append(node)
        last_at_depth[number] = node
        parent_of[number] = node
    if root is None:
        raise PTTParseError("empty PTT")
    return root
