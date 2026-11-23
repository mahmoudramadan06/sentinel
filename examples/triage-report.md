# Security Triage Report

- Target: `/home/sandbox/sentinel-triage/fixtures/vulnerable_app`
- Generated: 2026-11-22T02:53:03.120526+00:00 by sentinel-triage v0.1.0
- Files scanned: 4 (skipped: 0, duplicates removed: 3)
- LLM triage: mock (offline mock, not a real model)

## Summary

| Severity | Count |
| --- | --- |
| critical | 3 |
| high | 12 |
| medium | 1 |
| low | 1 |

## Findings (ranked by risk score)

### 1. AWS access key ID

- **Severity:** critical | **Confidence:** high | **Risk score:** 100.0
- **Location:** `app.py:14`
- **CWE:** CWE-798
- **Evidence:** `AWS_ACCESS_KEY = "AKIA************MPLE"`
- **Why it matters:** An AWS access key ID appears to be committed to the repository. Anyone with the matching secret key can act on the account.
- **Triage rationale:** [offline template] CRITICAL severity rule 'secret.aws-access-key' fired at app.py:14 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Rotate the key immediately in IAM, remove it from the code and git history, and load credentials from the environment or a secrets manager.
- **Investigation:** likely-placeholder (deterministic:secret planner, 2 steps, policy-done)
  The value matches placeholder/example patterns; rotate only if any real system ever used it, and keep dummy values obviously fake.
  - value looks like a placeholder/example (matched: example); length 20 (app.py:14)
  - AWS_ACCESS_KEY is not read from the environment anywhere (no locations)

### 2. minimist 1.2.5 affected by CVE-2021-44906

- **Severity:** critical | **Confidence:** high | **Risk score:** 100.0
- **Location:** `package.json:0`
- **Evidence:** `"minimist": "1.2.5"`
- **Why it matters:** minimist before 1.2.6 allows prototype pollution via crafted arguments.
- **Triage rationale:** [offline template] CRITICAL severity rule 'dep.npm.cve-2021-44906' fired at package.json:0 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Upgrade minimist to >= 1.2.6 (or 0.2.4 for the 0.x line).
- **Investigation:** no-literal-import (deterministic:dep planner, 1 steps, policy-done)
  No literal import of minimist found in the scanned tree. Dynamic imports (importlib, __import__, plugin entry points) and transitive use are not ruled out, so reachable-risk is probably lower, not zero; still upgrade.
  - minimist is never imported in the scanned tree (no locations)

### 3. pyyaml 5.3.1 affected by CVE-2020-14343

- **Severity:** critical | **Confidence:** high | **Risk score:** 100.0
- **Location:** `requirements.txt:4`
- **Evidence:** `pyyaml==5.3.1`
- **Why it matters:** PyYAML before 5.4: full_load / yaml.load with FullLoader can execute arbitrary code on untrusted input.
- **Triage rationale:** [offline template] CRITICAL severity rule 'dep.pypi.cve-2020-14343' fired at requirements.txt:4 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Upgrade PyYAML to >= 5.4 and prefer yaml.safe_load.
- **Investigation:** no-literal-import (deterministic:dep planner, 1 steps, policy-done)
  No literal import of pyyaml found in the scanned tree. Dynamic imports (importlib, __import__, plugin entry points) and transitive use are not ruled out, so reachable-risk is probably lower, not zero; still upgrade.
  - pyyaml is never imported in the scanned tree (no locations)

### 4. GitHub token

- **Severity:** high | **Confidence:** high | **Risk score:** 80.0
- **Location:** `app.py:18`
- **CWE:** CWE-798
- **Evidence:** `GITHUB_TOKE*******************************************000"  # fake placeholder`
- **Why it matters:** A GitHub personal access or OAuth token appears to be committed to the repository.
- **Triage rationale:** [offline template] HIGH severity rule 'secret.github-token' fired at app.py:18 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Revoke the token at github.com/settings/tokens, purge it from git history, and pass it via environment variables or a CI secret store.
- **Investigation:** likely-placeholder (deterministic:secret planner, 1 steps, policy-done)
  The value matches placeholder/example patterns; rotate only if any real system ever used it, and keep dummy values obviously fake.
  - value looks like a placeholder/example (matched: run:0000000000000000000000000000); length 41 (app.py:18)

### 5. requests 2.19.0 affected by CVE-2018-18074

- **Severity:** high | **Confidence:** high | **Risk score:** 80.0
- **Location:** `requirements.txt:1`
- **Evidence:** `requests==2.19.0`
- **Why it matters:** Requests before 2.20.0 sends the HTTP Authorization header to an https URI upon an http-to-https redirect.
- **Triage rationale:** [offline template] HIGH severity rule 'dep.pypi.cve-2018-18074' fired at requirements.txt:1 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Upgrade requests to >= 2.20.0.
- **Investigation:** no-literal-import (deterministic:dep planner, 1 steps, policy-done)
  No literal import of requests found in the scanned tree. Dynamic imports (importlib, __import__, plugin entry points) and transitive use are not ruled out, so reachable-risk is probably lower, not zero; still upgrade.
  - requests is never imported in the scanned tree (no locations)

### 6. urllib3 1.24.1 affected by CVE-2021-33503

- **Severity:** high | **Confidence:** high | **Risk score:** 80.0
- **Location:** `requirements.txt:2`
- **Evidence:** `urllib3==1.24.1`
- **Why it matters:** urllib3 before 1.26.5 allows catastrophic backtracking (ReDoS) via crafted URLs when an attacker controls the URL.
- **Triage rationale:** [offline template] HIGH severity rule 'dep.pypi.cve-2021-33503' fired at requirements.txt:2 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Upgrade urllib3 to >= 1.26.5.
- **Investigation:** no-literal-import (deterministic:dep planner, 1 steps, policy-done)
  No literal import of urllib3 found in the scanned tree. Dynamic imports (importlib, __import__, plugin entry points) and transitive use are not ruled out, so reachable-risk is probably lower, not zero; still upgrade.
  - urllib3 is never imported in the scanned tree (no locations)

### 7. flask 0.12.2 affected by CVE-2018-1000656

- **Severity:** high | **Confidence:** high | **Risk score:** 80.0
- **Location:** `requirements.txt:3`
- **Evidence:** `flask==0.12.2`
- **Why it matters:** Flask before 1.0 has a JSON denial-of-service issue (unbounded resource use decoding crafted JSON).
- **Triage rationale:** [offline template] HIGH severity rule 'dep.pypi.cve-2018-1000656' fired at requirements.txt:3 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Upgrade Flask to >= 1.0 (prefer a currently supported release).
- **Investigation:** no-literal-import (deterministic:dep planner, 1 steps, policy-done)
  No literal import of flask found in the scanned tree. Dynamic imports (importlib, __import__, plugin entry points) and transitive use are not ruled out, so reachable-risk is probably lower, not zero; still upgrade.
  - flask is never imported in the scanned tree (no locations)

### 8. Shell exec with template literal

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.js:9`
- **CWE:** CWE-78
- **Evidence:** `exec('logrotate --force /etc/logrotate.d/${name}');`
- **Why it matters:** child_process.exec with a template literal usually means interpolated input reaches a shell.
- **Triage rationale:** [offline template] HIGH severity rule 'code.js-child-process-template' fired at app.js:9 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use execFile/spawn with an argument array, and allowlist any values that reach the command.
- **Investigation:** unguarded-pattern (deterministic:js-sink planner, 1 steps, policy-done)
  No sanitizer or safe-sink usage found in the tree. This is regex-level evidence, not dataflow; treat user-reachable input to this sink as XSS until the value is escaped or traced to a trusted source.
  - no mitigation terms found: DOMPurify, sanitize(, sanitizeHtml, textContent (no locations)

### 9. Hardcoded credential assignment

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:16`
- **CWE:** CWE-798
- **Evidence:** `API_********************************000"  # fake placeholder for the generic rule`
- **Why it matters:** A credential-looking value is assigned as a string literal. Generic pattern: verify whether the value is a real credential or a placeholder.
- **Triage rationale:** [offline template] HIGH severity rule 'secret.generic-assignment' fired at app.py:16 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** If real, rotate it and move it to an environment variable or secrets manager; if a placeholder, replace it with an obvious dummy value.
- **Investigation:** likely-placeholder (deterministic:secret planner, 1 steps, policy-done)
  The value matches placeholder/example patterns; rotate only if any real system ever used it, and keep dummy values obviously fake.
  - value looks like a placeholder/example (matched: fake, run:0000000000000000); length 28 (app.py:16)

### 10. SQL built by string interpolation

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:23`
- **CWE:** CWE-89
- **Evidence:** `cur.execute(f"SELECT * FROM users WHERE name = '{name}'")`
- **Why it matters:** Building SQL with string interpolation or concatenation is the classic SQL injection pattern.
- **Triage rationale:** [offline template] HIGH severity rule 'code.sql-string-interpolation' fired at app.py:23 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use parameterized queries / prepared statements; never interpolate values into SQL text.
- **Investigation:** unguarded-pattern (deterministic:sql planner, 2 steps, policy-done)
  No input validation or escaping calls found in the flagged file. This is regex-level evidence, not dataflow: the value may still be constrained upstream. Treat the interpolation as injectable until it is parameterized or a dataflow check proves the input path safe.
  - 8: import hashlib (app.py:23)
  - no matches (no locations)

### 11. SQL built with Python % string formatting

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:29`
- **CWE:** CWE-89
- **Evidence:** `"VALUES ('%(name)s')" % {'name': name})`
- **Why it matters:** Applying % formatting to a SQL string interpolates values before the driver sees them, which is SQL injection when any value is user-influenced.
- **Triage rationale:** [offline template] HIGH severity rule 'code.sql-percent-format' fired at app.py:29 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Pass parameters separately (execute(query, params)) with the driver's placeholder style; never % or .format() values into SQL text.

### 12. Weak hash near password handling

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:34`
- **CWE:** CWE-327
- **Evidence:** `return hashlib.md5(password.encode()).hexdigest()`
- **Why it matters:** MD5/SHA-1 used to hash passwords is trivially crackable at scale.
- **Triage rationale:** [offline template] HIGH severity rule 'code.weak-hash-password-context' fired at app.py:34 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use a password KDF: bcrypt, scrypt, or Argon2id, with a per-user salt.

### 13. Subprocess with shell=True

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:38`
- **CWE:** CWE-78
- **Evidence:** `subprocess.run("generate-report " + report_name, shell=True)`
- **Why it matters:** Running a subprocess through the shell makes command injection likely if any part of the command string is influenced by input.
- **Triage rationale:** [offline template] HIGH severity rule 'code.python-shell-true' fired at app.py:38 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Pass arguments as a list with shell=False, and validate or allowlist any input that reaches the command.

### 14. Deserialization with pickle

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:42`
- **CWE:** CWE-502
- **Evidence:** `return pickle.loads(blob)`
- **Why it matters:** Unpickling attacker-controlled data is arbitrary code execution.
- **Triage rationale:** [offline template] HIGH severity rule 'code.python-pickle-load' fired at app.py:42 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use JSON or another data-only format for untrusted input; reserve pickle for trusted, integrity-checked local data.

### 15. Use of eval()

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `app.py:46`
- **CWE:** CWE-95
- **Evidence:** `return eval(expr)`
- **Why it matters:** eval() executes arbitrary Python. If the input is reachable by users it is remote code execution.
- **Triage rationale:** [offline template] HIGH severity rule 'code.python-eval' fired at app.py:46 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Replace eval() with ast.literal_eval for data, or an explicit parser/dispatch table for behavior.

### 16. innerHTML assignment

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `app.js:5`
- **CWE:** CWE-79
- **Evidence:** `document.getElementById("comments").innerHTML = text;`
- **Why it matters:** Assigning to innerHTML with data that includes user input is a DOM XSS sink.
- **Triage rationale:** [offline template] MEDIUM severity rule 'code.js-innerhtml' fired at app.js:5 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.

### 17. Debug mode enabled

- **Severity:** low | **Confidence:** high | **Risk score:** 40.0
- **Location:** `app.py:50`
- **CWE:** CWE-489
- **Evidence:** `debug = True`
- **Why it matters:** Framework debug mode (e.g. Flask/Django) exposes stack traces and, for some frameworks, an interactive console.
- **Triage rationale:** [offline template] LOW severity rule 'code.debug-mode-enabled' fired at app.py:50 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Drive debug mode from an environment flag that defaults to off in production.

---
Generated by sentinel-triage. Findings come from conservative pattern rules and a small offline advisory set; treat them as a prioritized review queue, not proof of exploitability.
