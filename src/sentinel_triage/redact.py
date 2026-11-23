"""Secret redaction. Findings and reports must never carry live credentials.

Two layers, on purpose:

1. Per-detector redaction: scanners mask at match time.
2. Central boundary scrub (this module's scrub_text / sanitize_finding):
   applied to EVERY finding from EVERY source in the triage pipeline, so a
   detector that forgets, or an imported finding carrying a secret in its
   evidence, cannot leak into a report or a provider payload.
"""

from __future__ import annotations

import json
import os
import re
from typing import List

_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "secrets.json")


def secret_patterns() -> List[re.Pattern]:
    """Compiled secret-detection patterns, shared by scanners and the scrubber."""
    with open(_RULES_PATH, "r", encoding="utf-8") as fh:
        return [re.compile(r["pattern"]) for r in json.load(fh)]


def mask_secret(value: str, keep: int = 4) -> str:
    """Mask a secret, keeping only its first and last `keep` characters.

    Short values are masked entirely so no usable fragment survives.
    """
    if not value:
        return "***"
    if len(value) <= keep * 2:
        return value[:2] + "*" * max(len(value) - 2, 4)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def mask_line(line: str, start: int, end: int) -> str:
    """Replace the span [start, end) inside a source line with a mask."""
    secret = line[start:end]
    return line[:start] + mask_secret(secret) + line[end:]


def scrub_text(text: str, patterns: List[re.Pattern] = None) -> str:
    """Mask every secret-pattern match in arbitrary text.

    Used at the pipeline boundary on all finding fields, regardless of
    which scanner or importer produced them.
    """
    if not text:
        return text
    if patterns is None:
        patterns = secret_patterns()
    out = []
    for line in str(text).splitlines() or [""]:
        for rx in patterns:
            matches = sorted(rx.finditer(line), key=lambda m: m.start(), reverse=True)
            for m in matches:
                line = mask_line(line, m.start(), m.end())
        out.append(line)
    return "\n".join(out)


_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")


def sanitize_markdown(text: str) -> str:
    """Neutralize active markup in untrusted text bound for a report.

    External endpoint output (LLM responses) and imported scanner output
    are untrusted: they could carry markdown images (tracking/exfil),
    links, or raw HTML that would render in the Markdown report. Images
    are dropped, links are flattened to their visible text, HTML tags are
    stripped, and backticks are neutralized so content cannot break out
    of inline-code spans.
    """
    if not text:
        return text
    text = _MD_IMAGE.sub("[image removed]", str(text))
    text = _MD_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    return text.replace("`", "'")


def clamp_snippet(snippet: str, limit: int = 160) -> str:
    """Bound snippet length so reports and LLM prompts stay small."""
    snippet = snippet.strip()
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 3] + "..."
