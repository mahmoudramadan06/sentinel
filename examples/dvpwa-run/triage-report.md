# Security Triage Report

- Target: `/tmp/dvpwa`
- Generated: 2026-11-22T02:53:02.881668+00:00 by sentinel-triage v0.1.0
- Files scanned: 27 (skipped: 31, duplicates removed: 3)
- LLM triage: mock (offline mock, not a real model)

## Summary

| Severity | Count |
| --- | --- |
| high | 2 |
| medium | 12 |
| low | 1 |

## Findings (ranked by risk score)

### 1. SQL built with Python % string formatting

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `sqli/dao/student.py:43`
- **CWE:** CWE-89
- **Evidence:** `"VALUES ('%(name)s')" % {'name': name})`
- **Why it matters:** Applying % formatting to a SQL string interpolates values before the driver sees them, which is SQL injection when any value is user-influenced.
- **Triage rationale:** [offline template] HIGH severity rule 'code.sql-percent-format' fired at sqli/dao/student.py:43 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Pass parameters separately (execute(query, params)) with the driver's placeholder style; never % or .format() values into SQL text.
- **Investigation:** unguarded-pattern (deterministic:sql planner, 2 steps, policy-done)
  No input validation or escaping calls found in the flagged file. This is regex-level evidence, not dataflow: the value may still be constrained upstream. Treat the interpolation as injectable until it is parameterized or a dataflow check proves the input path safe.
  - 28:         params = {} (sqli/dao/student.py:43)
  - no matches (no locations)

### 2. Weak hash near password handling

- **Severity:** high | **Confidence:** medium | **Risk score:** 64.0
- **Location:** `sqli/dao/user.py:41`
- **CWE:** CWE-327
- **Evidence:** `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()`
- **Why it matters:** MD5/SHA-1 used to hash passwords is trivially crackable at scale.
- **Triage rationale:** [offline template] HIGH severity rule 'code.weak-hash-password-context' fired at sqli/dao/user.py:41 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use a password KDF: bcrypt, scrypt, or Argon2id, with a per-user salt.
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - 31:     async def get_by_username(conn: Connection, username: str): (sqli/dao/user.py:41)

### 3. Semgrep Finding: yaml.docker-compose.security.no-new-privileges.no-new-privileges

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/docker-compose.yml:4`
- **Evidence:** `postgres:`
- **Why it matters:** Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges' fired at /tmp/dvpwa/docker-compose.yml:4 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/docker-compose.yml' (no locations)

### 4. Semgrep Finding: yaml.docker-compose.security.no-new-privileges.no-new-privileges

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/docker-compose.yml:14`
- **Evidence:** `redis:`
- **Why it matters:** Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges' fired at /tmp/dvpwa/docker-compose.yml:14 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/docker-compose.yml' (no locations)

### 5. Semgrep Finding: python.lang.security.audit.formatted-sql-query.formatted-sql-query

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/dao/student.py:45`
- **Evidence:** `await cur.execute(q)`
- **Why it matters:** Detected possible formatted SQL query. Use parameterized queries instead.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.python.lang.security.audit.formatted-sql-query.formatted-sql-query' fired at /tmp/dvpwa/sqli/dao/student.py:45 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Detected possible formatted SQL query. Use parameterized queries instead.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/dao/student.py' (no locations)

### 6. Semgrep Finding: python.lang.security.audit.md5-used-as-password.md5-used-as-password

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/dao/user.py:41`
- **Evidence:** `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()`
- **Why it matters:** It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use 'hashlib.scrypt'.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.python.lang.security.audit.md5-used-as-password.md5-used-as-password' fired at /tmp/dvpwa/sqli/dao/user.py:41 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use 'hashlib.scrypt'.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/dao/user.py' (no locations)

### 7. Semgrep Finding: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/static/js/materialize.js:565`
- **Evidence:** `e.classList ? e.classList.remove(t) : e.className = e.className.toString().replace(new RegExp("(^|\\s)" + t.split(" ").join("|") + "(\\s|$)", "gi"), " ");`
- **Why it matters:** RegExp() called with a '$ARG' function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as...
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp' fired at /tmp/dvpwa/sqli/static/js/materialize.js:565 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** RegExp() called with a '$ARG' function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as...
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js' (no locations)

### 8. Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/static/js/materialize.js:645`
- **Evidence:** `}return null === L.remToPx && (L.remToPx = parseFloat(S.getPropertyValue(r.body, "fontSize")) || 16), null === L.vwToPx && (L.vwToPx = parseFloat(t.innerWidt...`
- **Why it matters:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:645 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js' (no locations)

### 9. Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/static/js/materialize.js:661`
- **Evidence:** `var N = E[H].startValue;E[H].startValue = E[H].currentValue = E[H].endValue, E[H].endValue = N, m.isEmptyObject(v) || (E[H].easing = s.easing), b.debug && co...`
- **Why it matters:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:661 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js' (no locations)

### 10. Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `/tmp/dvpwa/sqli/static/js/materialize.js:699`
- **Evidence:** `q = M / q;}l[z] = { rootPropertyValue: B, startValue: M, currentValue: M, endValue: q, unitType: G, easing: $ }, b.debug && console.log("tweensContainer (" +...`
- **Why it matters:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
- **Triage rationale:** [offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:699 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.
💎 Enable cross-file analysis and Pro rules for free at sg.run/pro
- **Investigation:** needs-human-review (deterministic:generic planner, 1 steps, policy-done)
  Context gathered; no deterministic playbook exists for this rule family.
  - rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js' (no locations)

### 11. innerHTML assignment

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `sqli/static/js/materialize.js:396`
- **CWE:** CWE-79
- **Evidence:** `var t = r.createElement("div");if (t.innerHTML = "<!--[if IE " + e + "]><![endif]-->", t.getElementsByTagName("span").length) return t = null, e;`
- **Why it matters:** Assigning to innerHTML with data that includes user input is a DOM XSS sink.
- **Triage rationale:** [offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:396 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.

### 12. innerHTML assignment

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `sqli/static/js/materialize.js:3444`
- **CWE:** CWE-79
- **Evidence:** `toast.innerHTML = this.message;`
- **Why it matters:** Assigning to innerHTML with data that includes user input is a DOM XSS sink.
- **Triage rationale:** [offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:3444 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.

### 13. innerHTML assignment

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `sqli/static/js/materialize.js:8589`
- **CWE:** CWE-79
- **Evidence:** `el.innerHTML = '';`
- **Why it matters:** Assigning to innerHTML with data that includes user input is a DOM XSS sink.
- **Triage rationale:** [offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:8589 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.

### 14. innerHTML assignment

- **Severity:** medium | **Confidence:** medium | **Risk score:** 48.0
- **Location:** `sqli/static/js/materialize.js:8591`
- **CWE:** CWE-79
- **Evidence:** `el.innerHTML = '';`
- **Why it matters:** Assigning to innerHTML with data that includes user input is a DOM XSS sink.
- **Triage rationale:** [offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:8591 with medium confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.

### 15. Debug mode enabled

- **Severity:** low | **Confidence:** high | **Risk score:** 40.0
- **Location:** `sqli/app.py:24`
- **CWE:** CWE-489
- **Evidence:** `debug=True,`
- **Why it matters:** Framework debug mode (e.g. Flask/Django) exposes stack traces and, for some frameworks, an interactive console.
- **Triage rationale:** [offline template] LOW severity rule 'code.debug-mode-enabled' fired at sqli/app.py:24 with high confidence; ranked by the deterministic severity x confidence score.
- **Fix:** Drive debug mode from an environment flag that defaults to off in production.

---
Generated by sentinel-triage. Findings come from conservative pattern rules and a small offline advisory set; treat them as a prioritized review queue, not proof of exploitability.
