# sentinel

An authorized-scope security workbench for bug bounty and defensive testing,
built around one rule: **nothing touches a target unless a machine-checked
scope file allows it.**

It has two halves:

1. **Triage agent** (`scan`): scans a codebase for common problems
   (hardcoded secrets, dangerous code patterns, outdated dependencies),
   deduplicates the findings, ranks them by risk, and writes a prioritized
   remediation report in Markdown and JSON.
2. **Engagement workbench** (`scope`, `plan`, `recon`, `osint`): parses a
   scope file, builds a reconnaissance task tree (PTT) for the engagement,
   plans safe open-source recon tooling against in-scope targets (dry-run
   by default), and generates the passive OSINT checklist.

**Status: v0.2.** Useful, honestly scoped tooling with a tested offline
core; it is not an autonomous security agent and does not claim to be. See
"What is agentic here, and what is not" and "Honest limitations".

An optional LLM layer (Claude, or any OpenAI-compatible endpoint) adds
per-finding priority rationale and fix guidance. The core pipeline is
deterministic and works fully offline, so you can try it right now with no
API keys and no spend.

## What is agentic here, and what is not

Honesty about architecture matters more than the word "agent" on the
tin. The scan -> dedup -> rank pipeline is deterministic code: same
input, same output, fully testable offline. That is a feature, because
security output you cannot reproduce is output you cannot trust.

The agentic parts are:

1. **The investigation loop** (`--investigate`): for each top finding, a
   planner iteratively chooses read-only analysis actions (read context,
   regex search, usage/env/import checks, credential placeholder
   assessment, mitigation checks) over an indexed copy of the target,
   inspects the results, and reaches an evidence-qualified verdict
   (`likely-placeholder`, `possible-env-override`,
   `no-mitigating-evidence`, `unguarded-pattern`,
   `imported-with-advisory`, `no-literal-import`,
   `needs-human-review`) with per-step provenance. The vocabulary is
   deliberately heuristic: the deterministic planners perform no
   dataflow, so labels name what was actually observed ("no guard calls
   in the flagged file", "no literal import found") instead of claiming
   confirmed risk or verified mitigation. It is bounded by
   design: a closed action allowlist, no shell, no writes, no network,
   hard step/output caps, and every observation passes the central
   redaction boundary. The default planner is a deterministic per-family
   playbook (honest, reproducible, offline); `--investigate-with-llm`
   swaps in an LLM planner that picks from the same allowlist as JSON,
   is validated the same way, and degrades safely to the deterministic
   planner on any invalid or unsafe choice.
2. **The optional LLM triage layer**, which reads the ranked findings and
   writes per-finding rationale and fix guidance through a provider
   adapter, with validation and deterministic fallback.
3. **The repo itself**, which is set up for agentic coding tools to
   operate (see below).

sentinel-triage does not autonomously probe, exploit, or change
anything, and it never will. Where a deterministic planner cannot verify
a claim (e.g. whether a guard actually covers an input path), it says
`needs-human-review` instead of guessing.

## Why this exists

Security scanners are noisy. Running Semgrep, Trivy, or pip-audit on a real
project produces piles of output: duplicates, out-of-scope hits, and no
sense of what to fix first. Triage, turning that noise into a short ranked
list with a concrete fix per item, is where the actual time goes.
sentinel-triage automates that workflow end to end:

1. **Scan**: three built-in scanners (secrets, code patterns, dependencies).
2. **Deduplicate**: exact duplicates and same-line rule collisions are merged.
3. **Rank**: deterministic severity x confidence scoring, same input always
   gives the same order.
4. **Explain**: optional LLM pass writes a rationale and fix per finding.
   If the provider fails or returns garbage, the tool falls back to
   deterministic output and says so in the report.

## Quickstart

```bash
git clone <this repo>
cd sentinel-triage
pip install -e .

# Fully offline demo against the bundled synthetic vulnerable app:
sentinel-triage demo

# Scan your own project:
sentinel-triage scan /path/to/your/project

# Triage real scanner noise: dedup/rank/explain Semgrep, CodeQL or Trivy
# output (SARIF format), on its own or merged with the built-in scanners:
sentinel-triage scan /path/to/your/project --sarif semgrep-results.sarif

# Investigate the top findings: bounded read-only analysis actions, a
# verdict and evidence trail per finding (deterministic, offline):
sentinel-triage scan /path/to/your/project --investigate
```

Reports land in `sentinel-output/` as `triage-report.md` and
`triage-report.json`. See `examples/` for a real generated report.

## Provider status (read this before trusting output)

| Provider | Status |
| --- | --- |
| `mock` (default) | Fully offline deterministic templates. **Not a language model.** Used by the test suite and demo. Reports always say `llm_is_mock: true`. |
| `anthropic` | Implemented (Messages API, `ANTHROPIC_API_KEY`, model override via `SENTINEL_ANTHROPIC_MODEL`). Request/response handling is unit-tested with a stubbed transport. **Not yet exercised against the live API.** |
| `openai` | Implemented for any OpenAI-compatible endpoint: OpenAI, OpenRouter, Ollama, LM Studio (`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`). Unit-tested with a stubbed transport. **Not yet exercised against a live endpoint.** |

Nothing in this project claims a live model call succeeded when it did not.
Every report records which provider ran and whether it was the mock.

## Using it with agentic coding tools (OpenCode, Claude Code)

Tools and providers are different layers. OpenCode
(https://opencode.ai) and Claude Code are agentic coding tools (they
operate a repo); Anthropic Claude and OpenAI-compatible endpoints are
model providers (they answer prompts). This project supports both
layers, separately:

- For coding tools, the repo ships `AGENTS.md` (read natively by
  OpenCode, per opencode.ai/docs/instructions) plus a `CLAUDE.md`
  pointer for Claude Code, so they can run scans, add rules, and extend
  the pipeline with the project's own conventions.
- For model providers, the triage layer talks to them directly through
  the adapters in the table above.

See docs/research.md for the landscape analysis behind this design and
docs/validation.md for everything that was actually run and verified.

## Engagement workbench

A scope file is plain JSON (or a minimal YAML subset):

```json
{
  "engagement": "Acme Q4 authorized bug bounty",
  "targets": ["example.com", "10.0.0.0/24"],
  "exclusions": ["admin.example.com"],
  "allow_active": false
}
```

```bash
# Validate a scope file and test targets against it:
sentinel-triage scope scope.json --check api.example.com --check admin.example.com

# Build the reconnaissance task tree (PTT) for the engagement, offline:
sentinel-triage plan scope.json

# See the exact recon commands it would run (dry-run is the default):
sentinel-triage recon scope.json

# Actually run them - only what the scope allows, re-validated at
# execution time including a fresh DNS resolution check:
sentinel-triage recon scope.json --execute

# Print the passive OSINT checklist (pure query building, no network):
sentinel-triage osint scope.json
```

The recon registry is a fixed set of plugins wrapping standard open-source
tools (subfinder, Amass, dig, whois, httpx, katana, nmap, nuclei) with
allowlisted flags only: passive plugins run against scoped targets;
active plugins additionally require `allow_active: true`; intrusive
families (exploits, brute force, fuzzing, NSE scripts) are not available
at all. nuclei is present as a planning aid but its live execution is
disabled: `-tags tech` is a moving upstream tag set, not a pinned,
reviewed template allowlist, so it stays dry-run only until specific
reviewed templates are vendored. nmap service detection is real probe
traffic to in-scope addresses, not a passive read. There is no way to
pass arbitrary flags, and no shell is ever invoked.

The PTT task-tree core is forked from
[PentestGPT](https://github.com/GreyDGL/PentestGPT) (MIT) with substantive
changes: a real tested data model instead of prompt-only text, scope-gated
task creation, a deterministic offline planner, and the removal of
upstream prompt text that asserted approvals nobody checked. See
`THIRD_PARTY_NOTICES.md`.

## Safety and scope

- **Defensive only.** Scan code you own or are explicitly authorized to test.
  Run the engagement workbench only against targets listed in a scope you
  are authorized to test.
- **Scope is enforced in code, not in docs.** Every live action validates
  its target against the scope file; exclusions always win; live runs
  re-check the target's DNS answers at execution time and refuse
  out-of-scope resolutions.
- **Dry-run by default.** `recon` prints the exact commands and runs
  nothing until `--execute` is passed, and even then only for in-scope
  targets with the required activity level.
- **Read-only.** Scanners never modify, execute, or exfiltrate target files.
  There is no subprocess and no network access in the scanning code path.
- **Redaction first, twice.** Secrets are masked at detection time, and
  every finding from every source then passes a central boundary scrub
  before dedup, reports, or any LLM payload. A detector that forgets to
  redact, or imported scanner output carrying a live secret, still cannot
  leak. Regression tests cover every ingest and output path.
  LLM providers receive finding metadata only, never file contents.
- **No autonomous offensive actions.** The tool does not exploit, probe, or
  attack anything. It produces a review queue for a human.

## Managing false positives: baseline

Reviewed a finding and accepted it? Put its fingerprint (from the JSON
report) in `.sentinel-baseline.json` at the target root:

```json
{"suppressed": ["0123abcd4567ef89"]}
```

Suppressed findings disappear from future reports, and the suppressed
count is disclosed in report metadata. Minified build artifacts
(`*.min.js` and friends) are skipped by policy; vendored unminified
third-party code is scanned and belongs in the baseline once reviewed.

## What it finds

- Hardcoded secrets: AWS keys, GitHub tokens, private key blocks, Slack
  webhooks, generic credential assignments (CWE-798, CWE-321).
- Dangerous code patterns: `shell=True`, `eval()`, `pickle.loads`, SQL
  string interpolation, `innerHTML` assignment, template-literal shell
  exec, MD5/SHA-1 password hashing, debug mode left on.
- Dependency advisories: pinned versions in `requirements.txt` and
  `package.json` checked against a small built-in advisory set.

## Honest limitations

- Detection is regex-based. It will miss things a real SAST engine catches
  and it will produce some false positives (the generic credential rule is
  marked medium confidence for this reason).
- The built-in advisory set is intentionally tiny (8 advisories) and is a
  demonstration, not a CVE feed. For real dependency work, pair this with
  osv-scanner or pip-audit.
- The LLM layer explains and prioritizes; it does not change severities,
  and hallucinated findings are discarded automatically.
- The investigation loop reads only what the scanners can see (source
  text of the target). It cannot execute the target, resolve runtime
  config, or follow build-time indirection, so `needs-human-review` is a
  common and honest outcome.
- Live web-plugin runs are tunneled through Sentinel's loopback egress
  proxy (`sentinel proxy`, auto-started by `recon --execute`), which
  re-checks scope per request and dials only DNS-validated addresses, so
  redirects and DNS flips cannot pull the tool out of scope. This was
  verified against the real binaries in a loopback lab (httpx v1.12.0,
  katana v1.8.0; see `docs/validation.md`): in-scope requests passed,
  direct out-of-scope requests and crawled out-of-scope links were
  refused, and even the binaries' own chatter to an unrelated hardcoded
  hostname was refused. Limits: the proxy bounds the tools' documented
  HTTP path only - a binary can in principle open raw sockets or leak
  through DNS, and CONNECT pins one connection, not all process traffic,
  so this is scope enforcement for legitimate tools, not a sandbox or
  network isolation. nuclei stays dry-run only because `-tags tech` is a
  moving upstream tag set, not a pinned, reviewed template allowlist.
  nmap cannot use an HTTP proxy, so its live argv carries only the
  DNS-validated IP literals (capped at 8) and nmap resolves nothing
  itself - but it sends real probe traffic to those addresses.
- Passive enumeration (subfinder, Amass) queries public passive-DNS
  databases, which discloses the target names to those third-party
  services. That is inherent to passive recon; only the `osint` module
  performs no network access at all.
- Hosts discovered in tool output are re-validated against the scope
  (with a live DNS re-check on the execute path) so out-of-scope
  discoveries are labelled and never become the next stage's target.
- Passive enumeration (subfinder, Amass) queries public passive-DNS
  databases, which discloses the target names to those third-party
  services. That is inherent to passive recon; only the `osint` module
  performs no network access at all.
- The keyword gate on LLM-proposed plan revisions is defense-in-depth,
  not the primary control. The primary control is that the plan tree
  cannot execute anything: only the fixed recon playbook and registry
  run, whatever the tree says.

## Roadmap

- GitHub Action that posts the triage report as a PR comment.
- More deterministic investigation playbooks (XSS sinks, SSRF, path
  traversal) as real-target evidence justifies them.
- Normalizing recon plugin output into the Finding schema and merging it
  into the triage report.
- Rate limiting and politeness controls (per-host budgets, concurrency
  caps) for live recon.
- A findings data store so engagements accumulate deduplicated evidence
  across runs.
- Live-vendor validation of the two provider adapters and the LLM
  investigation planner, then a tagged 1.0.0.

## Development

```bash
pip install -e ".[test]"
python -m pytest tests/ -q   # 145 tests, fully offline
```

Rules live in `src/sentinel_triage/rules/*.json`; advisories in
`src/sentinel_triage/data/advisories.json`. Add entries, run the tests,
done. `fixtures/vulnerable_app/` is synthetic and must never contain real
credentials; the AWS key there is AWS's own published documentation
example.

## License and attribution

MIT (see `LICENSE`). The PTT task-tree core under
`src/sentinel_triage/ptree/` is forked from PentestGPT (MIT,
Copyright (c) 2023 Grey_D) with substantive changes listed in
`THIRD_PARTY_NOTICES.md`; its license text is preserved under
`third_party/pentestgpt/`. CVE summaries in `data/advisories.json`
paraphrase the public NVD/OSV records for the cited CVE IDs. The recon
plugins invoke third-party tools installed on the operator's machine; they
are not vendored and remain under their own licenses.
