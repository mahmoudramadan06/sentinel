"""Isolated regex-search worker. Standalone on purpose: no package imports.

The parent (actions.search) sends a JSON request on stdin:
    {"pattern": str, "files": {path: [lines]}, "max_matches": int}
and reads a JSON response on stdout:
    {"hits": ["path:lineno: line", ...], "truncated": bool}
or  {"error": str}

Why a separate process: the stdlib regex engine backtracks
exponentially on ambiguous patterns (nested quantifiers, but also
group-free shapes like 20 optional atoms followed by 20 required
atoms). No in-process timer can interrupt one re.search call, and no
static pattern scan covers every ambiguous shape. Running the match
here lets the parent enforce a real runtime bound: kill the process on
timeout and report a clean failure. Secret scrubbing stays in the
parent; this worker only matches and truncates.
"""

import json
import re
import sys

MAX_LINE_MATCH = 1000    # chars of a line fed to the regex engine
MAX_LINE_SCAN = 100_000  # total lines examined per request
MAX_MATCHES = 25
HIT_LINE_CHARS = 140


def main() -> None:
    try:
        req = json.load(sys.stdin)
        pattern = req["pattern"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("pattern missing")
        rx = re.compile(pattern)
        max_matches = max(1, min(int(req.get("max_matches", MAX_MATCHES)), MAX_MATCHES))
        files = req["files"]
        if not isinstance(files, dict):
            raise ValueError("files missing")
    except Exception as exc:
        json.dump({"error": str(exc)}, sys.stdout)
        return

    hits = []
    scanned = 0
    truncated = False
    for path, lines in files.items():
        for lineno, line in enumerate(lines, start=1):
            scanned += 1
            if scanned > MAX_LINE_SCAN:
                truncated = True
                break
            if rx.search(str(line)[:MAX_LINE_MATCH]):
                hits.append(f"{path}:{lineno}: {str(line).strip()[:HIT_LINE_CHARS]}")
                if len(hits) >= max_matches:
                    break
        if truncated or len(hits) >= max_matches:
            break
    json.dump({"hits": hits, "truncated": truncated}, sys.stdout)


if __name__ == "__main__":
    main()
