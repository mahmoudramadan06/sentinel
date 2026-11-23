"""Safety guards.

sentinel-triage is a defensive, read-only tool. These guards make that
structural rather than a promise in the README:

* The scanner only ever opens files for reading, only inside the target
  directory the user pointed it at.
* No scanner spawns subprocesses or opens network connections. The only
  network-capable code in the project lives in the optional LLM provider
  adapters, which send redacted finding metadata (never file contents)
  and only when the user explicitly selects a provider.
* Binary files, huge files, and common dependency directories are skipped.
"""

from __future__ import annotations

import os
from typing import Iterator, Tuple

MAX_FILE_BYTES = 1_000_000  # 1 MB
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".idea", ".vscode", ".tox",
}
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".cs", ".sh", ".bash", ".zsh", ".ps1",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".xml", ".tf", ".dockerfile", ".txt", ".md",
}
SCANNABLE_BASENAMES = {"dockerfile", "makefile", ".env", ".env.local", ".env.example"}


def is_minified_artifact(name: str) -> bool:
    """Minified build artifacts (jquery.min.js, app.min.css) are generated,
    not authored. Flagging them is the classic scanner-noise complaint, so
    they are skipped; vendored unminified third-party code is still scanned
    (suppress reviewed hits with the baseline file)."""
    base = name.lower()
    return ".min." in base


class GuardError(Exception):
    """Raised when a scan request violates the safety guards."""


def resolve_target(target: str) -> str:
    """Resolve and validate the scan target directory."""
    path = os.path.realpath(os.path.expanduser(target))
    if not os.path.isdir(path):
        raise GuardError(f"scan target is not a directory: {target}")
    return path


def iter_files(target: str) -> Iterator[Tuple[str, str, int]]:
    """Yield (relative_path, absolute_path, skipped_flag) for scannable files.

    Files that fail the guards are yielded with skipped_flag=1 and no
    absolute path, so callers can count them without ever opening them.
    """
    root = resolve_target(target)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            abs_path = os.path.join(dirpath, name)
            # A symlinked file must not lead the scanner outside the target.
            if not os.path.realpath(abs_path).startswith(root + os.sep):
                yield os.path.relpath(abs_path, root), "", 1
                continue
            rel_path = os.path.relpath(abs_path, root)
            base = name.lower()
            ext = os.path.splitext(base)[1]
            if is_minified_artifact(base):
                yield os.path.relpath(abs_path, root), "", 1
                continue
            if ext not in SCANNABLE_EXTENSIONS and base not in SCANNABLE_BASENAMES:
                yield rel_path, "", 1
                continue
            try:
                if os.path.getsize(abs_path) > MAX_FILE_BYTES:
                    yield rel_path, "", 1
                    continue
            except OSError:
                yield rel_path, "", 1
                continue
            yield rel_path, abs_path, 0


def read_text(abs_path: str) -> str:
    """Read a file as UTF-8 text; raises UnicodeDecodeError for binary."""
    with open(abs_path, "r", encoding="utf-8") as fh:
        return fh.read()


def load_target(target: str):
    """Walk the target once and read every scannable file.

    Returns (contents, scanned, skipped) where contents is a list of
    (relative_path, text). `scanned` counts only files actually read;
    guard-skipped AND undecodable/binary files both count as `skipped`,
    so the report never overstates how much was scanned.
    """
    contents = []
    scanned = 0
    skipped = 0
    for rel_path, abs_path, skip_flag in iter_files(target):
        if skip_flag:
            skipped += 1
            continue
        try:
            text = read_text(abs_path)
        except (UnicodeDecodeError, OSError):
            skipped += 1
            continue
        contents.append((rel_path, text))
        scanned += 1
    return contents, scanned, skipped
