{
  "metadata": {
    "tool": "sentinel-triage",
    "version": "0.1.0",
    "generated_at": "2026-11-22T02:53:02.882183+00:00",
    "target": "/tmp/dvpwa",
    "files_scanned": 27,
    "files_skipped": 31,
    "duplicates_removed": 3,
    "baseline_suppressed": 0,
    "warnings": [],
    "investigations_planner": "deterministic",
    "investigations_run": 10,
    "llm_provider": "mock",
    "llm_used": true,
    "llm_is_mock": true
  },
  "severity_counts": {
    "info": 0,
    "low": 1,
    "medium": 12,
    "high": 2,
    "critical": 0
  },
  "findings": [
    {
      "fingerprint": "c0c0371dba4e67a6",
      "rule_id": "code.sql-percent-format",
      "title": "SQL built with Python % string formatting",
      "severity": "high",
      "confidence": "medium",
      "risk_score": 64.0,
      "file": "sqli/dao/student.py",
      "line": 43,
      "snippet": "\"VALUES ('%(name)s')\" % {'name': name})",
      "description": "Applying % formatting to a SQL string interpolates values before the driver sees them, which is SQL injection when any value is user-influenced.",
      "remediation": "Pass parameters separately (execute(query, params)) with the driver's placeholder style; never % or .format() values into SQL text.",
      "source": "patterns",
      "cwe": "CWE-89",
      "triage_note": {
        "priority_rationale": "[offline template] HIGH severity rule 'code.sql-percent-format' fired at sqli/dao/student.py:43 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Pass parameters separately (execute(query, params)) with the driver's placeholder style; never % or .format() values into SQL text."
      },
      "investigation": {
        "fingerprint": "c0c0371dba4e67a6",
        "verdict": "unguarded-pattern",
        "planner": "deterministic:sql",
        "summary": "No input validation or escaping calls found in the flagged file. This is regex-level evidence, not dataflow: the value may still be constrained upstream. Treat the interpolation as injectable until it is parameterized or a dataflow check proves the input path safe.",
        "evidence": [
          {
            "note": "28:         params = {}\n29:         if limit is not None:\n30:             q += ' LIMIT + %(limit)s '\n31:             params['limit'] = limit\n32:         if offset is not None:\n33:             q += ' OFFSET + %(offset)s '\n34:             params['offset'] = offset\n35:         async with conn.cursor...",
            "sources": [
              "sqli/dao/student.py:43"
            ],
            "via": "read_context"
          },
          {
            "note": "no matches",
            "sources": [],
            "via": "search"
          }
        ],
        "steps": 2,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "sqli/dao/student.py",
              "line": 43,
              "radius": 15
            },
            "ok": true,
            "observation": "28:         params = {}\n29:         if limit is not None:\n30:             q += ' LIMIT + %(limit)s '\n31:             params['limit'] = limit\n32:         if offset is not None:\n33:             q += ' OFFSET + %(offset)s '\n34:             params['offset'] = offset\n35:         async with conn.cursor() as cur:\n36:             await cur.execute(q, params)\n37:             results = await cur.fetchall()\n38:             return [Student.from_raw(r) for r in results]\n39: \n40:     @staticmethod\n41:     async def create(conn: Connection, name: str):\n42:         q = (\"INSERT INTO students (name) \"\n43:  ..."
          },
          {
            "step": 2,
            "action": "search",
            "args": {
              "pattern": "\\bint\\(|\\bisdigit\\(|\\ballowlist\\b|\\bwhitelist\\b|\\b(?:sanitize|escape|validate)[a-z_]*\\s*\\(|re\\.(?:match|fullmatch)\\(",
              "file": "sqli/dao/student.py"
            },
            "ok": true,
            "observation": "no matches"
          }
        ]
      }
    },
    {
      "fingerprint": "f6327f6847ced57d",
      "rule_id": "code.weak-hash-password-context",
      "title": "Weak hash near password handling",
      "severity": "high",
      "confidence": "medium",
      "risk_score": 64.0,
      "file": "sqli/dao/user.py",
      "line": 41,
      "snippet": "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()",
      "description": "MD5/SHA-1 used to hash passwords is trivially crackable at scale.",
      "remediation": "Use a password KDF: bcrypt, scrypt, or Argon2id, with a per-user salt.",
      "source": "patterns",
      "cwe": "CWE-327",
      "triage_note": {
        "priority_rationale": "[offline template] HIGH severity rule 'code.weak-hash-password-context' fired at sqli/dao/user.py:41 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Use a password KDF: bcrypt, scrypt, or Argon2id, with a per-user salt."
      },
      "investigation": {
        "fingerprint": "f6327f6847ced57d",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "31:     async def get_by_username(conn: Connection, username: str):\n32:         async with conn.cursor() as cur:\n33:             await cur.execute(\n34:                 'SELECT id, first_name, middle_name, last_name, '\n35:                 'username, pwd_hash, is_admin FROM users WHERE username = %...",
            "sources": [
              "sqli/dao/user.py:41"
            ],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "sqli/dao/user.py",
              "line": 41,
              "radius": 10
            },
            "ok": true,
            "observation": "31:     async def get_by_username(conn: Connection, username: str):\n32:         async with conn.cursor() as cur:\n33:             await cur.execute(\n34:                 'SELECT id, first_name, middle_name, last_name, '\n35:                 'username, pwd_hash, is_admin FROM users WHERE username = %s',\n36:                 (username,),\n37:             )\n38:             return User.from_raw(await cur.fetchone())\n39: \n40:     def check_password(self, password: str):\n41:         return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()"
          }
        ]
      }
    },
    {
      "fingerprint": "7402d9aa46f95f95",
      "rule_id": "sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges",
      "title": "Semgrep Finding: yaml.docker-compose.security.no-new-privileges.no-new-privileges",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/docker-compose.yml",
      "line": 4,
      "snippet": "postgres:",
      "description": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.",
      "remediation": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges' fired at /tmp/dvpwa/docker-compose.yml:4 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "7402d9aa46f95f95",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/docker-compose.yml'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/docker-compose.yml",
              "line": 4,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/docker-compose.yml'"
          }
        ]
      }
    },
    {
      "fingerprint": "46f04becc027e77d",
      "rule_id": "sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges",
      "title": "Semgrep Finding: yaml.docker-compose.security.no-new-privileges.no-new-privileges",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/docker-compose.yml",
      "line": 14,
      "snippet": "redis:",
      "description": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.",
      "remediation": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.yaml.docker-compose.security.no-new-privileges.no-new-privileges' fired at /tmp/dvpwa/docker-compose.yml:14 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "46f04becc027e77d",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/docker-compose.yml'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/docker-compose.yml",
              "line": 14,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/docker-compose.yml'"
          }
        ]
      }
    },
    {
      "fingerprint": "4b9f3b5f199811ea",
      "rule_id": "sarif.Semgrep OSS.python.lang.security.audit.formatted-sql-query.formatted-sql-query",
      "title": "Semgrep Finding: python.lang.security.audit.formatted-sql-query.formatted-sql-query",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/dao/student.py",
      "line": 45,
      "snippet": "await cur.execute(q)",
      "description": "Detected possible formatted SQL query. Use parameterized queries instead.",
      "remediation": "Detected possible formatted SQL query. Use parameterized queries instead.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.python.lang.security.audit.formatted-sql-query.formatted-sql-query' fired at /tmp/dvpwa/sqli/dao/student.py:45 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Detected possible formatted SQL query. Use parameterized queries instead.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "4b9f3b5f199811ea",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/dao/student.py'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/dao/student.py",
              "line": 45,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/dao/student.py'"
          }
        ]
      }
    },
    {
      "fingerprint": "493612a7c7340bf4",
      "rule_id": "sarif.Semgrep OSS.python.lang.security.audit.md5-used-as-password.md5-used-as-password",
      "title": "Semgrep Finding: python.lang.security.audit.md5-used-as-password.md5-used-as-password",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/dao/user.py",
      "line": 41,
      "snippet": "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()",
      "description": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use 'hashlib.scrypt'.",
      "remediation": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use 'hashlib.scrypt'.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.python.lang.security.audit.md5-used-as-password.md5-used-as-password' fired at /tmp/dvpwa/sqli/dao/user.py:41 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use 'hashlib.scrypt'.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "493612a7c7340bf4",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/dao/user.py'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/dao/user.py",
              "line": 41,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/dao/user.py'"
          }
        ]
      }
    },
    {
      "fingerprint": "9c7cf035ee405622",
      "rule_id": "sarif.Semgrep OSS.javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
      "title": "Semgrep Finding: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
      "line": 565,
      "snippet": "e.classList ? e.classList.remove(t) : e.className = e.className.toString().replace(new RegExp(\"(^|\\\\s)\" + t.split(\" \").join(\"|\") + \"(\\\\s|$)\", \"gi\"), \" \");",
      "description": "RegExp() called with a '$ARG' function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as...",
      "remediation": "RegExp() called with a '$ARG' function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as...",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp' fired at /tmp/dvpwa/sqli/static/js/materialize.js:565 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "RegExp() called with a '$ARG' function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as..."
      },
      "investigation": {
        "fingerprint": "9c7cf035ee405622",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
              "line": 565,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'"
          }
        ]
      }
    },
    {
      "fingerprint": "313bc28703087d0e",
      "rule_id": "sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "title": "Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
      "line": 645,
      "snippet": "}return null === L.remToPx && (L.remToPx = parseFloat(S.getPropertyValue(r.body, \"fontSize\")) || 16), null === L.vwToPx && (L.vwToPx = parseFloat(t.innerWidt...",
      "description": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.",
      "remediation": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:645 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "313bc28703087d0e",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
              "line": 645,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'"
          }
        ]
      }
    },
    {
      "fingerprint": "3ebaaa0b5deca89b",
      "rule_id": "sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "title": "Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
      "line": 661,
      "snippet": "var N = E[H].startValue;E[H].startValue = E[H].currentValue = E[H].endValue, E[H].endValue = N, m.isEmptyObject(v) || (E[H].easing = s.easing), b.debug && co...",
      "description": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.",
      "remediation": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:661 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "3ebaaa0b5deca89b",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
              "line": 661,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'"
          }
        ]
      }
    },
    {
      "fingerprint": "1fd1f3742c37ce58",
      "rule_id": "sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "title": "Semgrep Finding: javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
      "line": 699,
      "snippet": "q = M / q;}l[z] = { rootPropertyValue: B, startValue: M, currentValue: M, endValue: q, unitType: G, easing: $ }, b.debug && console.log(\"tweensContainer (\" +...",
      "description": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.",
      "remediation": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro",
      "source": "sarif:Semgrep OSS",
      "cwe": null,
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'sarif.Semgrep OSS.javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring' fired at /tmp/dvpwa/sqli/static/js/materialize.js:699 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.\n\ud83d\udc8e Enable cross-file analysis and Pro rules for free at sg.run/pro"
      },
      "investigation": {
        "fingerprint": "1fd1f3742c37ce58",
        "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "Context gathered; no deterministic playbook exists for this rule family.",
        "evidence": [
          {
            "note": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'",
            "sources": [],
            "via": "read_context"
          }
        ],
        "steps": 1,
        "stopped_by": "policy-done",
        "transcript": [
          {
            "step": 1,
            "action": "read_context",
            "args": {
              "file": "/tmp/dvpwa/sqli/static/js/materialize.js",
              "line": 699,
              "radius": 10
            },
            "ok": false,
            "observation": "rejected: unknown file '/tmp/dvpwa/sqli/static/js/materialize.js'"
          }
        ]
      }
    },
    {
      "fingerprint": "b68bfcfdbb47b175",
      "rule_id": "code.js-innerhtml",
      "title": "innerHTML assignment",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "sqli/static/js/materialize.js",
      "line": 396,
      "snippet": "var t = r.createElement(\"div\");if (t.innerHTML = \"<!--[if IE \" + e + \"]><![endif]-->\", t.getElementsByTagName(\"span\").length) return t = null, e;",
      "description": "Assigning to innerHTML with data that includes user input is a DOM XSS sink.",
      "remediation": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.",
      "source": "patterns",
      "cwe": "CWE-79",
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:396 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML."
      }
    },
    {
      "fingerprint": "7d5c5a305832d4a6",
      "rule_id": "code.js-innerhtml",
      "title": "innerHTML assignment",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "sqli/static/js/materialize.js",
      "line": 3444,
      "snippet": "toast.innerHTML = this.message;",
      "description": "Assigning to innerHTML with data that includes user input is a DOM XSS sink.",
      "remediation": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.",
      "source": "patterns",
      "cwe": "CWE-79",
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:3444 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML."
      }
    },
    {
      "fingerprint": "7863b3f3171204fe",
      "rule_id": "code.js-innerhtml",
      "title": "innerHTML assignment",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "sqli/static/js/materialize.js",
      "line": 8589,
      "snippet": "el.innerHTML = '';",
      "description": "Assigning to innerHTML with data that includes user input is a DOM XSS sink.",
      "remediation": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.",
      "source": "patterns",
      "cwe": "CWE-79",
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:8589 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML."
      }
    },
    {
      "fingerprint": "f5423b4c25eee1b7",
      "rule_id": "code.js-innerhtml",
      "title": "innerHTML assignment",
      "severity": "medium",
      "confidence": "medium",
      "risk_score": 48.0,
      "file": "sqli/static/js/materialize.js",
      "line": 8591,
      "snippet": "el.innerHTML = '';",
      "description": "Assigning to innerHTML with data that includes user input is a DOM XSS sink.",
      "remediation": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML.",
      "source": "patterns",
      "cwe": "CWE-79",
      "triage_note": {
        "priority_rationale": "[offline template] MEDIUM severity rule 'code.js-innerhtml' fired at sqli/static/js/materialize.js:8591 with medium confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Use textContent for plain text, or sanitize with a vetted library (e.g. DOMPurify) before writing HTML."
      }
    },
    {
      "fingerprint": "bd284a80d7bb0456",
      "rule_id": "code.debug-mode-enabled",
      "title": "Debug mode enabled",
      "severity": "low",
      "confidence": "high",
      "risk_score": 40.0,
      "file": "sqli/app.py",
      "line": 24,
      "snippet": "debug=True,",
      "description": "Framework debug mode (e.g. Flask/Django) exposes stack traces and, for some frameworks, an interactive console.",
      "remediation": "Drive debug mode from an environment flag that defaults to off in production.",
      "source": "patterns",
      "cwe": "CWE-489",
      "triage_note": {
        "priority_rationale": "[offline template] LOW severity rule 'code.debug-mode-enabled' fired at sqli/app.py:24 with high confidence; ranked by the deterministic severity x confidence score.",
        "fix_guidance": "Drive debug mode from an environment flag that defaults to off in production."
      }
    }
  ]
}
