"""Deterministic offline provider.

MockProvider is NOT a language model. It produces structured triage notes
from finding metadata with fixed templates, which makes the whole pipeline
testable without API keys, network access, or spend. Reports generated
with it always carry `"llm_is_mock": true`.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .base import Provider


class MockProvider(Provider):
    name = "mock"
    is_mock = True

    def complete(self, system: str, user: str) -> str:
        payload = json.loads(user)
        notes: List[Dict[str, str]] = []
        for f in payload.get("findings", []):
            sev = f["severity"]
            notes.append(
                {
                    "fingerprint": f["fingerprint"],
                    "priority_rationale": (
                        f"[offline template] {sev.upper()} severity rule "
                        f"'{f['rule_id']}' fired at {f['file']}:{f['line']} "
                        f"with {f['confidence']} confidence; ranked by the "
                        f"deterministic severity x confidence score."
                    ),
                    "fix_guidance": f["remediation"],
                }
            )
        return json.dumps({"triage": notes}, indent=2)
