"""The triage agent: orchestrates scan -> dedup -> rank -> explain.

Stage 1-3 are deterministic. Stage 4 optionally asks an LLM provider for
per-finding rationale and fix guidance. The LLM response is validated
against the actual finding set; anything unparseable or hallucinated
(unknown fingerprints) is discarded, and the pipeline falls back to
deterministic output with `llm_used=False` so the report never
overstates what happened.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List

from .dedup import deduplicate
from .models import Finding, ScanResult
from .providers import Provider, ProviderError
from .rank import rank_findings
from .scanners import scan_code_patterns, scan_dependencies, scan_secrets

SYSTEM_PROMPT = (
    "You are a defensive security triage assistant. You receive deduplicated "
    "findings from local scanners (already redacted: no live secrets, no file "
    "contents). For each finding, write a one-sentence priority rationale and "
    "concise fix guidance. Reply with ONLY a JSON object of the form "
    '{"triage": [{"fingerprint": "...", "priority_rationale": "...", '
    '"fix_guidance": "..."}]}. Do not invent findings, do not change severity, '
    "do not ask questions. The operator is responsible for running this tool "
    "only on codebases they are authorized to review; if the findings suggest "
    "otherwise, decline to assist."
)

MAX_FINDINGS_FOR_LLM = 25


def sanitize_finding(f: Finding) -> Finding:
    """Central boundary scrub: mask secret-pattern matches in every text
    field of a finding, from any source. Per-detector redaction is the
    first layer; this second layer means no detector or importer has to
    be trusted with redaction on its own."""
    from dataclasses import replace

    from .redact import sanitize_markdown, scrub_text

    def clean(field_value: str) -> str:
        # Secret masking AND markup neutralization: finding text comes from
        # scanned code and external scanner files, both untrusted.
        return sanitize_markdown(scrub_text(field_value))

    return replace(
        f,
        title=clean(f.title),
        snippet=clean(f.snippet),
        description=clean(f.description),
        remediation=clean(f.remediation),
    )


def collect_findings(target: str, sarif_files: List[str] = None,
                     baseline_path: str = None, use_osv: bool = False) -> ScanResult:
    """Run all scanners, merge any imported SARIF output, and consolidate.

    The target is walked and read exactly once; every finding from every
    source passes the central boundary scrub before dedup, so downstream
    stages (dedup, ranking, reports, provider payloads) only ever see
    masked content. Baseline suppressions are applied after dedup; the
    suppressed count is disclosed in the report.
    """
    from .baseline import apply_baseline, load_baseline
    from .guards import load_target
    from .importers import import_sarif

    contents, files_scanned, files_skipped = load_target(target)

    all_findings: List[Finding] = []
    all_findings.extend(scan_secrets(contents))
    all_findings.extend(scan_code_patterns(contents))
    all_findings.extend(scan_dependencies(contents))
    for sarif_path in sarif_files or []:
        all_findings.extend(import_sarif(sarif_path))

    warnings: List[str] = []
    if use_osv:
        from .osv_client import OsvError, query_osv
        from .scanners.deps import iter_dependencies

        try:
            all_findings.extend(query_osv(list(iter_dependencies(contents))))
        except OsvError as exc:
            warnings.append(
                f"online OSV lookup failed ({exc}); showing built-in offline "
                "advisory results only"
            )

    all_findings = [sanitize_finding(f) for f in all_findings]

    unique, removed = deduplicate(all_findings)
    kept, suppressed_count = apply_baseline(unique, load_baseline(target, baseline_path))
    return ScanResult(
        target=target,
        findings=rank_findings(kept),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        duplicates_removed=removed,
        baseline_suppressed=suppressed_count,
        warnings=warnings,
    )


def _extract_json(text: str) -> Dict:
    """Pull the first JSON object out of a model response."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("no JSON object in response")
    return json.loads(m.group(0))


def run_investigations(result: ScanResult, provider: Provider = None,
                       use_llm_planner: bool = False,
                       max_findings: int = 10) -> ScanResult:
    """Investigate the top findings with the bounded agent loop.

    Deterministic playbooks by default; with use_llm_planner=True a real
    (non-mock) provider chooses actions. Either way the loop enforces the
    same allowlist, limits, scrubbing, and provenance.
    """
    from .agent import Limits, TargetIndex, investigate
    from .agent.policies import policy_for
    from .guards import load_target

    contents, _scanned, _skipped = load_target(result.target)
    index = TargetIndex(contents)

    for finding in result.findings[:max(0, max_findings)]:
        if use_llm_planner:
            from .agent.llm_planner import LLMPlanner

            if provider is None or provider.is_mock:
                raise ProviderError(
                    "--investigate-with-llm needs a real provider "
                    "(--provider anthropic|openai); the mock is not a model"
                )
            planner = LLMPlanner(provider)
        else:
            planner = policy_for(finding)
        inv = investigate(finding, index, planner, Limits())
        result.investigations[finding.fingerprint()] = inv.to_dict()
        result.investigations_planner = planner.name.split(":")[0]
    return result


def triage_with_llm(result: ScanResult, provider: Provider) -> ScanResult:
    """Attach LLM triage notes to the top findings.

    On any provider or parsing failure the result is returned with
    llm_used=False and a note explaining the fallback. Reports therefore
    always reflect what actually ran.
    """
    result.llm_provider = provider.name
    result.llm_is_mock = provider.is_mock

    top = result.findings[:MAX_FINDINGS_FOR_LLM]
    payload = {"findings": [f.to_dict() for f in top]}
    try:
        raw = provider.complete(SYSTEM_PROMPT, json.dumps(payload))
        data = _extract_json(raw)
        notes = data.get("triage", [])
        if not isinstance(notes, list):
            raise ValueError("'triage' is not a list")
    except (ProviderError, ValueError, json.JSONDecodeError) as exc:
        result.llm_used = False
        result.triage_notes = {
            "_error": {"detail": f"LLM triage skipped: {exc}"}
        }
        return result

    from .redact import sanitize_markdown, scrub_text

    def clean_note(value) -> str:
        # Provider output is untrusted: mask secret-pattern text and
        # neutralize markup before it reaches any report.
        return sanitize_markdown(scrub_text(str(value or "")))

    known = {f.fingerprint() for f in top}
    clean: Dict[str, Dict[str, str]] = {}
    for note in notes:
        if not isinstance(note, dict):
            continue
        fp = note.get("fingerprint")
        if fp in known:
            clean[fp] = {
                "priority_rationale": clean_note(note.get("priority_rationale")),
                "fix_guidance": clean_note(note.get("fix_guidance")),
            }
    result.triage_notes = clean
    result.llm_used = True
    return result
