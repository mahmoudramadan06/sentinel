# Validation record

## Independent audit, investigation-loop review (2026-11-22)

A fresh independent review of the investigation increment verified the
test suite, loop bounds and read-only restrictions, and found four
concrete issues, all fixed with structural changes and regressions
(89 tests total):

1. Markup injection through the investigation renderer: planner-return
   summaries and evidence notes bypassed the markup neutralizer, so a
   hostile provider (or a target file whose lines become evidence)
   could plant remote images/links/HTML in reports. Fix: a single
   `_safe_text` boundary in the loop scrubs secret patterns,
   neutralizes markup and clamps length on every planner summary and
   observation BEFORE it enters the transcript/evidence, and the
   Markdown renderer additionally sanitizes every investigation string
   it emits (defense in depth for any dict that reaches the renderer).
   Regressions: hostile Done summary asserted absent from JSON+MD;
   hand-built malicious investigation dict neutralized at render.
2. ReDoS through planner-supplied regex, two rounds. Round one: a
   nested-quantifier probe hung the stdlib engine; a static safety scan
   was added to reject backreferences, nested quantifiers and
   quantified alternation groups pre-compile. Round two (recheck): a
   GROUP-FREE ambiguous pattern - 20 optional atoms followed by 20
   required atoms, end-anchored - hung a 999-character line for >20s
   despite the scan, and the between-lines timer could not interrupt a
   single re.search call. Structural fix: every search now runs in an
   isolated worker process (_search_worker.py, no package imports)
   with a hard timeout and kill (6s); the parent turns a timeout into a
   clean rejected observation, so no pattern - known shape or not -
   can hang a scan. The static scan remains only as a fast-path
   rejection; the process kill is the actual runtime bound, and docs
   now say so. Matched lines are length-capped in the worker; payloads
   to the worker are size-capped. Regressions: six catastrophic-pattern
   shapes rejected by the fast path, and the auditor's group-free
   reproducer verified killed within the hard budget; policy guard
   patterns and common safe shapes still pass.
3. Placeholder false positives: substring fragments ("chan", "test",
   "exam") matched inside live-looking values ("merchant", "contest")
   and downgraded them to likely-placeholder. Fix: curated whole-word
   vocabulary with alphabetic boundaries plus structural runs
   (xxxx/0000/1111/1234). Regressions: fragment-containing live value
   stays non-placeholder; AWS's documented example key, TEST- values
   and run-values still classify as placeholder.
4. Report bloat: planner-returned summaries were unbounded (a 200k-char
   summary reached the report). Fix: summaries capped at 600 chars at
   the same `_safe_text` boundary; transcript args and stored
   observations clamped per-field. Regression: oversized hostile summary
   capped and cleaned.

Also removed the committed-then-zipped build/ duplicate snapshot and
added a .gitignore; the release zip is source-only again.

## Investigation loop (2026-11-22)

The `--investigate` increment adds a bounded agency layer: a planner
chooses from a closed allowlist of read-only actions over an indexed
copy of the target, gathers evidence, and emits an evidence-qualified
verdict with per-step provenance. Validated as follows:

- 23 offline tests (83 total): action argument validation and caps,
  evidence truncation, per-family policy decision trees, loop step
  limits and stop reasons, a scripted LLM planner (valid picks,
  invalid/unsafe picks falling back to the deterministic planner), and
  an end-to-end scan with investigations enabled.
- Real targets: dvpwa (SQLi at student.py:43 -> `unguarded-pattern`;
  findings with no playbook -> `needs-human-review`) and the bundled
  fixture (AWS example key -> `likely-placeholder`; fixture SQLi ->
  `unguarded-pattern`; advisories for packages with no literal import
  -> `no-literal-import`). itsdangerous still scans clean.
- Self-caught correctness bug, fixed before the increment commit: the
  SQL guard check originally searched the whole tree, so
  `autoescape=False` in dvpwa's app.py and `re.match` in vendored
  materialize.js counted as "mitigation" for a SQLi in student.py and
  produced a wrong verdict on a known-real injection. The guard search
  is now scoped to the flagged file, guard patterns require
  function-call shape (`escape` the substring no longer matches
  `autoescape=False`), and an in-file guard yields
  `needs-human-review` rather than any mitigated label, because a
  deterministic planner cannot verify the guard covers the flagged
  input path. A regression test reproduces the dvpwa layout.

### Verdict vocabulary hardened after correctness review (2026-11-22)

Independent review (via the coordinating agent) flagged that the first
vocabulary overclaimed: `confirmed-risk` asserted exploitability from
regex evidence, `likely-mitigated` asserted mitigation an env override
does not prove (a hardcoded fallback can remain live), and
`not-imported` ignored dynamic/transitive imports. The vocabulary is
now evidence-qualified - each label names what was observed, not a
conclusion:

- `likely-placeholder` - value matches placeholder/example patterns.
- `possible-env-override` - non-placeholder literal whose identifier is
  also read from the environment elsewhere; the summary states the
  hardcoded fallback may remain live.
- `no-mitigating-evidence` - non-placeholder literal, no env override
  found in the tree; the summary states absence of evidence is not
  proof of absence.
- `unguarded-pattern` - no guard/sanitizer calls found in scope; the
  summary states this is regex-level evidence, not dataflow.
- `imported-with-advisory` - literal import plus advisory for the
  pinned version; the summary states vulnerable-function reachability
  is not established.
- `no-literal-import` - no literal import found; the summary states
  dynamic imports and transitive use are not ruled out.
- `needs-human-review` / `partial-evidence` - fallback labels.

`confirmed-risk`, `likely-mitigated` and `not-imported` were removed
from the allowed verdict set entirely (the loop validates planner
output against the set, so no planner can emit them). Adversarial
regression tests assert the caveats survive: env override must not read
as mitigation, cross-file guard noise must not mitigate a SQLi, and
`no-literal-import` must carry the dynamic-import caveat.

- Live LLM planning (`--investigate-with-llm` against a real provider)
  remains unverified: no keys, no spend. All LLM-planner tests use a
  scripted in-process client; the mock refusal and fallback paths are
  covered.

## Independent audit, round 2 (2026-11-22)

Recheck confirmed the round-1 fixes, then found one more boundary gap:
LLM provider RETURN text (priority_rationale / fix_guidance) bypassed
redaction, so a malicious or malfunctioning endpoint could inject
secret-pattern text or active markup (markdown images/links, raw HTML)
into reports. Fixes: provider-returned notes are now masked with the
secret patterns AND neutralized for markup (images dropped, links
flattened to visible text, HTML stripped, backticks neutralized) before
they can reach JSON or Markdown output; the same markup neutralization
applies centrally to all finding fields, which also covers untrusted
SARIF rule text. Regression tests: a MaliciousProvider planting a secret
plus markup (asserted absent from both reports) and a SARIF file with
injected links/HTML.

## Opt-in online OSV lookup

- `--osv` queries the public OSV API (POST /v1/querybatch, one request,
  no key) and merges results with source "deps:osv"; same-line
  duplicates against the built-in demo set merge, ties prefer OSV.
- Offline default unchanged; OSV failure falls back to the built-in set
  with a disclosed warning, never a crash.
- Tested over real HTTP against a local stub returning a recorded
  response in the documented OSV schema (request shape, severity
  mapping, HTTP-500 handling, pipeline fallback and merge).
- LIVE-validated 2026-11-22 against api.osv.dev (public, no key, no
  spend): one querybatch for 6 pinned packages returned 47 advisories
  across the 5 known-vulnerable ones (urllib3 26, requests 10, flask 8,
  pyyaml 2, minimist 1) and none for itsdangerous 2.1.2, in 0.34 s;
  the full CLI run with `--osv` merged them onto the 5 dependency
  findings (family-aware dedup, ties prefer OSV).

## Independent audit, round 1 (2026-11-22)

An independent review reproduced the test suite and documented scope, and
found one release-blocking issue plus minors. All fixed and covered by new
regression tests (tests/test_redaction_boundary.py):

- BLOCKER: a code-pattern finding's raw source-line snippet could carry a
  live secret into the JSON/Markdown report and the LLM provider payload,
  and same-line dedup could discard the masked secrets finding while
  keeping the leaky one. Fixes: (1) central boundary scrub: every finding
  from every source (secrets, patterns, deps, SARIF) is re-masked in the
  pipeline before dedup, so redaction no longer depends on each detector;
  (2) collision merge now only merges within the same source family, so a
  secrets finding and a pattern finding on one line are both kept, both
  masked. Regression tests assert every ingest path and every output path
  (JSON, Markdown, recorded provider payload) carry no raw secret.
- Minor: advisory count corrected (8, not 7) in README.
- Minor: undecodable/binary files were counted as scanned; the target is
  now walked and read exactly once and only successfully read files count
  as scanned, everything else as skipped.
- Minor: requirements with extras (requests[security]==2.19.0) were
  silently skipped; extras are now parsed and the base package checked.
  Inline comments in requirements lines are stripped.
- Minor: the LLM system prompt asserted authorization ("this is
  authorized..."); it now requires it ("the operator is responsible for
  running this tool only on codebases they are authorized to review; if
  the findings suggest otherwise, decline to assist").

What was actually run before this project was called ready. Everything
below was executed locally and offline on 2026-11-22; commands are
reproducible. No vendor API was called and no money was spent.

## Test suite

- 83 tests, all passing (`python -m pytest tests/ -q`), fully offline.
- Re-run against the installed wheel (not just the source tree): pass.

## Packaging

- `python -m build` produces an sdist and a wheel.
- The wheel was installed into a clean venv; `sentinel-triage --version`
  and a real scan work from the installed package (rules and advisory
  data ship correctly).
- `sentinel-triage demo` from an installed package fails cleanly with a
  clear message (fixtures are intentionally not shipped); from a source
  checkout it works.

## Realistic targets

### dvpwa (https://github.com/anxolerd/dvpwa, intentionally vulnerable training app)

Cloned at commit on 2026-11-22, scanned read-only. This scan drove three
real improvements, listed with the evidence:

- True positives found: MD5 used for password hashing
  (`sqli/dao/user.py:41`, confirmed by reading the source: it compares
  `md5(password)` to the stored hash); debug mode enabled
  (`sqli/app.py:24`).
- Noise class found and handled: minified vendored JS (jquery.min.js,
  materialize.min.js) originally produced most of the findings.
  Minified artifacts are now skipped by policy; unminified vendored
  materialize.js still flags `innerHTML` 4 times. That is a real
  limitation: the tool cannot tell vendored third-party code from
  authored code. The baseline file is the intended answer (review once,
  suppress by fingerprint).
- Honest miss, then a fix driven by ground truth: the first scan found
  no SQL injection. A real Semgrep run (479 rules, 46 files, 11
  findings, SARIF imported via `--sarif`) flagged
  `sqli/dao/student.py:45`: `"VALUES ('%(name)s')" % {'name': name}`,
  a genuine injection. A new `code.sql-percent-format` rule now catches
  this pattern (closing quote followed by `% {`, i.e. values
  interpolated by Python before the driver sees them) while correctly
  ignoring both safe pyformat-parameterized styles elsewhere in the same
  file. Verified: dvpwa scan now flags student.py as high; the clean
  repo still has zero findings.
- Cross-tool agreement: Semgrep independently flagged the same MD5
  password hashing at user.py:41.

Final dvpwa numbers: internal scanners alone, 27 files, 7 findings
(2 high: SQLi + MD5, 4 medium vendored innerHTML, 1 low debug). With the
real Semgrep SARIF merged: 15 unique findings, 3 duplicates removed.

### itsdangerous (https://github.com/pallets/itsdangerous, clean and maintained)

- 21 files scanned, 0 findings. No false positives on a healthy codebase.

### Bundled synthetic fixture (fixtures/vulnerable_app)

- 4 files, 19 unique findings, 4 duplicates removed (exercises exact
  dedup and same-line collision merge), severities 3 critical / 13 high
  / 2 medium / 1 low, including the merged SARIF import path
  (`--sarif fixtures/semgrep-output.sarif`).

### Real Semgrep end-to-end

- Semgrep 1.186.0 (`--config p/default --sarif`) against dvpwa produced
  a 2.1 MB SARIF with 11 findings; sentinel-triage imported, deduplicated,
  ranked, and reported them alongside its own. Command:
  `sentinel-triage scan /tmp/dvpwa --sarif /tmp/dvpwa.sarif --no-llm`.

## Adversarial and failure cases (all tested)

- Malformed SARIF (not JSON, wrong version, missing `runs`, junk types
  inside): clean `error: ...` message, exit code 2, no traceback.
- SARIF snippet containing a live-looking AWS key: masked at import,
  verified absent from the final JSON report.
- Symlink pointing outside the scan target: skipped, never read.
- Binary file, oversized file (>1MB): skipped, counted.
- Empty directory: valid empty report, not an error.
- Hand-written clean module (parameterized SQL, pbkdf2, shell=False):
  zero findings, i.e. no eager false positives.
- LLM provider raising mid-run: report falls back to deterministic
  ranking and discloses `llm_used=false` plus the reason.
- LLM hallucinating unknown finding fingerprints: notes discarded.

## Provider adapters: what "tested" means here

- The Anthropic and OpenAI-compatible adapters were exercised over real
  HTTP against a local schema-compatible stub server
  (`tests/test_hardening.py`): correct paths, auth headers, request
  bodies, and response parsing, no mocks of urllib.
- They have NOT been exercised against the live vendor APIs: that needs
  a key and someone's spend approval, and the request shape can still
  drift from what a vendor expects. This is stated in README
  "Provider status"; treat live use as first-run-unverified until one
  real call with a real key succeeds.
- The mock provider (default) is deterministic templates, labeled as
  not-a-model in the CLI, the reports, and the metadata.

## Known sharp edges

- The generic credential rule can false-positive on placeholder strings
  that look like secrets (medium confidence by design; suppress via
  baseline).
- `.env.example`-style files with dummy secrets will flag; that is
  intentional, dummy values belong in obvious placeholder form.
- SARIF severity mapping is conservative (error->high, warning->medium)
  because SARIF levels carry no impact context.
