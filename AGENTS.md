# AGENTS.md

Instructions for AI coding agents (OpenCode, Claude Code, and similar)
working in this repository.

## What this project is

sentinel-triage is a defensive security triage agent. It scans a codebase
for secrets, dangerous patterns, and outdated dependencies, deduplicates
and ranks the findings, and writes a remediation report. An optional LLM
layer (Claude / OpenAI-compatible) adds per-finding explanations. The core
pipeline is deterministic and fully offline.

## Setup and verification

```bash
pip install -e ".[test]"
python -m pytest tests/ -q      # all tests must pass, fully offline
sentinel-triage demo            # end-to-end smoke run on bundled fixtures
```

Run these before and after any change. Never claim the pipeline works
without running them.

## Layout

- `src/sentinel_triage/scanners/` - the three scanners (secrets, patterns, deps)
- `src/sentinel_triage/rules/` - detection rules as JSON, one file per scanner
- `src/sentinel_triage/data/advisories.json` - small offline advisory set
- `src/sentinel_triage/dedup.py`, `rank.py` - consolidation and ranking
- `src/sentinel_triage/providers/` - LLM adapters (mock, anthropic, openai)
- `src/sentinel_triage/triager.py` - pipeline orchestration
- `src/sentinel_triage/report.py` - Markdown/JSON report generation
- `fixtures/vulnerable_app/` - synthetic test target, never real credentials
- `tests/` - pytest suite, must stay fully offline

## Rules for agents

1. This is a defensive, read-only tool. Do not add exploitation, probing,
   or any offensive capability. Do not add network calls outside
   `providers/`.
2. Secrets must stay redacted: anything matched by the secrets scanner is
   masked before it leaves the scanner. Do not weaken this.
3. The mock provider is labeled as not-a-real-model everywhere it
   surfaces. Do not remove those labels or imply live model calls in
   tests, docs, or output.
4. Keep the test suite offline: no live API calls, no network fixtures.
5. New detection capability goes into `rules/*.json` plus a fixture line
   plus a test, in the same change.
6. Update README's "Provider status" and "Honest limitations" sections
   whenever behavior changes.
